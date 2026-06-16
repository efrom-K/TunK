use std::ffi::OsString;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use anyhow::{anyhow, Result};

use crate::network::route::RouteManager;
use crate::network::dispatch;
use crate::state::AppState;

/// Имя пула адаптеров Wintun, используемое этим приложением.
const WINTUN_POOL: &str = "TunK";

/// Маска /32, используемая для маршрута-исключения адреса прокси-сервера.
const HOST_MASK: Ipv4Addr = Ipv4Addr::new(255, 255, 255, 255);

/// Метрика, устанавливаемая на Wintun-интерфейс, чтобы он стал маршрутом
/// с наивысшим приоритетом (весь трафик идёт через туннель).
const TUNNEL_METRIC: u32 = 1;

/// Метрика маршрута-исключения для прокси-сервера (через реальный шлюз).
const EXCLUSION_METRIC: u32 = 1;

/// IP-адрес, назначаемый на Wintun-интерфейс — шлюз FakeIP-подсети `198.18.0.0/16`.
/// Без этого адреса ОС не знает, как маршрутизировать пакеты к TUN-адаптеру.
const TUN_ADDRESS: Ipv4Addr = Ipv4Addr::new(198, 18, 0, 1);

/// Маска подсети FakeIP-пула (`/16`).
const TUN_NETMASK: Ipv4Addr = Ipv4Addr::new(255, 255, 0, 0);

/// Находит `wintun.dll` на диске.
///
/// Сначала проверяет директорию запущенного исполняемого файла — именно туда
/// Tauri копирует ресурсы при сборке и установке. Если там нет — возвращает
/// просто имя файла, и ОС ищет его сама через PATH / CWD.
fn locate_wintun_dll() -> OsString {
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let candidate = dir.join("wintun.dll");
            if candidate.exists() {
                return candidate.into_os_string();
            }
        }
    }
    OsString::from("wintun.dll")
}

/// Активная сессия Wintun: адаптер должен жить не меньше, чем связанная с ним сессия.
struct WintunSession {
    adapter: Arc<wintun::Adapter>,
    session: Arc<wintun::Session>,
}

/// Обёртка над виртуальным сетевым адаптером Wintun.
pub struct WintunAdapter {
    interface_name: String,
    mtu: u32,
    is_active: AtomicBool,
    session: Mutex<Option<WintunSession>>,
}

impl WintunAdapter {
    pub fn new(interface_name: &str) -> Result<Self> {
        Ok(Self {
            interface_name: interface_name.to_string(),
            mtu: 1420,
            is_active: AtomicBool::new(false),
            session: Mutex::new(None),
        })
    }

    /// Загружает драйвер wintun.dll, открывает (или создаёт) виртуальный адаптер
    /// и запускает сессию обмена пакетами.
    pub fn activate(&self) -> Result<()> {
        // SAFETY: загружается стандартный подписанный wintun.dll; путь выбирается
        // функцией locate_wintun_dll() — сначала рядом с exe, затем PATH/CWD.
        let wintun = unsafe { wintun::load_from_path(locate_wintun_dll()) }
            .map_err(|e| anyhow!("Не удалось загрузить wintun.dll: {}", e))?;

        let adapter = match wintun::Adapter::open(&wintun, WINTUN_POOL, &self.interface_name) {
            Ok(adapter) => adapter,
            Err(_) => {
                wintun::Adapter::create(&wintun, WINTUN_POOL, &self.interface_name, None)
                    .map_err(|e| anyhow!("Не удалось создать адаптер Wintun: {}", e))?
                    .adapter
            }
        };

        let session = adapter
            .start_session(wintun::MAX_RING_CAPACITY)
            .map_err(|e| anyhow!("Не удалось запустить сессию Wintun: {}", e))?;

        let mut guard = self.session.lock().map_err(|e| anyhow!("Не удалось заблокировать сессию: {}", e))?;
        *guard = Some(WintunSession {
            adapter: Arc::new(adapter),
            session: Arc::new(session),
        });

        // Assign the static IP address to the TUN interface.  Without this the OS has no
        // subnet route pointing at the adapter and cannot deliver packets to it.
        RouteManager::set_interface_address(&self.interface_name, TUN_ADDRESS, TUN_NETMASK)
            .map_err(|e| anyhow!("Не удалось назначить IP {} на {}: {}", TUN_ADDRESS, self.interface_name, e))?;

        self.is_active.store(true, Ordering::SeqCst);
        Ok(())
    }

    /// Останавливает сессию и освобождает ресурсы адаптера.
    pub fn deactivate(&self) -> Result<()> {
        let mut guard = self.session.lock().map_err(|e| anyhow!("Не удалось заблокировать сессию: {}", e))?;

        if let Some(wintun_session) = guard.take() {
            wintun_session.session.shutdown();
        }

        // Best-effort: remove the static IP so the dormant interface has no stale address.
        let _ = RouteManager::clear_interface_address(&self.interface_name);

        self.is_active.store(false, Ordering::SeqCst);
        Ok(())
    }

    /// Возвращает индекс интерфейса Windows, необходимый для команд маршрутизации.
    pub fn get_adapter_index(&self) -> Result<u32> {
        let guard = self.session.lock().map_err(|e| anyhow!("Не удалось заблокировать сессию: {}", e))?;
        let wintun_session = guard
            .as_ref()
            .ok_or_else(|| anyhow!("Адаптер Wintun не активирован"))?;

        wintun_session
            .adapter
            .get_adapter_index()
            .map_err(|e| anyhow!("Не удалось получить индекс адаптера: {}", e))
    }

    /// Настраивает таблицу маршрутизации и DNS для работы VPN:
    /// 1. /32 маршрут-исключение для прокси через реальный шлюз (против петли).
    /// 2. Метрика TUN-интерфейса = 1 (наивысший приоритет).
    /// 3. Split-default 0.0.0.0/1 + 128.0.0.0/1 через TUN — перебивает /0 по LPM.
    /// 4. DNS 127.0.0.1 на TUN-интерфейс — Windows DNS Client выбирает его первым.
    /// 5. Сброс DNS-кэша (best-effort).
    pub fn configure_routing(&self, proxy_server: Ipv4Addr) -> Result<()> {
        let interface_index = self.get_adapter_index()?;
        let gateway = RouteManager::get_default_gateway()?;

        RouteManager::add_route(proxy_server, HOST_MASK, gateway, EXCLUSION_METRIC)?;
        RouteManager::set_interface_metric(interface_index, TUNNEL_METRIC)?;
        RouteManager::add_split_default_route(TUN_ADDRESS, TUNNEL_METRIC)?;
        RouteManager::set_interface_dns(&self.interface_name, Ipv4Addr::new(127, 0, 0, 1))?;
        // Best-effort: a stale cache is not fatal — new queries will reach our proxy anyway.
        let _ = RouteManager::flush_dns_cache();

        Ok(())
    }

    /// Откатывает все изменения, сделанные в [`configure_routing`]:
    /// удаляет /32 исключение прокси, split-default маршруты, DNS с TUN-интерфейса.
    /// Все шаги выполняются всегда, ошибки объединяются в одну.
    pub fn restore_routing(&self, proxy_server: Ipv4Addr) -> Result<()> {
        let errs: Vec<String> = [
            RouteManager::delete_route(proxy_server, HOST_MASK).err(),
            RouteManager::delete_split_default_route().err(),
            RouteManager::clear_interface_dns(&self.interface_name).err(),
        ]
        .into_iter()
        .flatten()
        .map(|e| e.to_string())
        .collect();

        // Best-effort flush regardless of errors above.
        let _ = RouteManager::flush_dns_cache();

        if errs.is_empty() {
            Ok(())
        } else {
            Err(anyhow!("{}", errs.join("; ")))
        }
    }

    /// Returns the active Wintun session, or an error if not yet activated.
    pub fn get_session(&self) -> Result<Arc<wintun::Session>> {
        let guard = self.session.lock().map_err(|e| anyhow!("{}", e))?;
        guard
            .as_ref()
            .map(|ws| ws.session.clone())
            .ok_or_else(|| anyhow!("Wintun session not active"))
    }

    /// Reads packets from the Wintun session and dispatches each TCP flow
    /// destined for the FakeIP range to a proxy relay task.
    /// Returns when `deactivate()` is called (which shuts down the session).
    pub async fn packet_loop(&self, state: Arc<AppState>) -> Result<()> {
        let session = self.get_session()?;
        dispatch::run_dispatch(session, state).await
    }

    pub fn get_interface_name(&self) -> &str {
        &self.interface_name
    }

    pub fn get_mtu(&self) -> u32 {
        self.mtu
    }

    pub fn is_active(&self) -> bool {
        self.is_active.load(Ordering::SeqCst)
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_locate_wintun_dll_filename() {
        let path = locate_wintun_dll();
        let s = path.to_string_lossy();
        // Regardless of which search path is chosen, must end with "wintun.dll".
        assert!(s.ends_with("wintun.dll"), "unexpected path: {}", s);
    }

    #[test]
    fn test_tun_address_constants() {
        assert_eq!(TUN_ADDRESS, Ipv4Addr::new(198, 18, 0, 1));
        assert_eq!(TUN_NETMASK, Ipv4Addr::new(255, 255, 0, 0));
        // Verify the address is within the FakeIP pool (198.18.0.0/16).
        let octets = TUN_ADDRESS.octets();
        assert_eq!(octets[0], 198);
        assert_eq!(octets[1], 18);
    }

    #[test]
    fn test_wintun_adapter_creation() {
        let adapter = WintunAdapter::new("vpn-tun").unwrap();
        assert_eq!(adapter.get_interface_name(), "vpn-tun");
        assert_eq!(adapter.get_mtu(), 1420);
        assert!(!adapter.is_active());
    }

    #[test]
    fn test_get_adapter_index_before_activation() {
        let adapter = WintunAdapter::new("vpn-tun").unwrap();
        assert!(adapter.get_adapter_index().is_err());
    }

    #[test]
    fn test_get_session_before_activation() {
        let adapter = WintunAdapter::new("vpn-tun").unwrap();
        assert!(adapter.get_session().is_err());
    }

    #[tokio::test]
    async fn test_packet_loop_without_activation() {
        let state = Arc::new(AppState::new());
        let adapter = WintunAdapter::new("vpn-tun").unwrap();
        // Without an active session, packet_loop must return Err immediately.
        assert!(adapter.packet_loop(state).await.is_err());
    }

    #[test]
    #[ignore = "requires wintun.dll and administrator privileges"]
    fn test_wintun_activation() {
        let adapter = WintunAdapter::new("vpn-tun").unwrap();
        adapter.activate().unwrap();
        assert!(adapter.is_active());
        adapter.deactivate().unwrap();
        assert!(!adapter.is_active());
    }

    #[tokio::test]
    #[ignore = "requires wintun.dll and administrator privileges"]
    async fn test_packet_loop_runs_until_deactivate() {
        let state = Arc::new(AppState::new());
        let adapter = WintunAdapter::new("vpn-tun").unwrap();
        adapter.activate().unwrap();
        tokio::time::timeout(
            tokio::time::Duration::from_millis(100),
            adapter.packet_loop(state),
        )
        .await
        .ok();
        assert!(adapter.is_active());
    }

    #[test]
    #[ignore = "requires wintun.dll and administrator privileges"]
    fn test_configure_routing() {
        let adapter = WintunAdapter::new("vpn-tun").unwrap();
        adapter.activate().unwrap();
        let proxy_server = Ipv4Addr::new(1, 2, 3, 4);
        adapter.configure_routing(proxy_server).unwrap();
        adapter.restore_routing(proxy_server).unwrap();
    }
}
