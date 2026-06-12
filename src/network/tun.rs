use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use anyhow::{anyhow, Result};

use crate::network::route::RouteManager;

/// Имя пула адаптеров Wintun, используемое этим приложением.
const WINTUN_POOL: &str = "TunK";

/// Маска /32, используемая для маршрута-исключения адреса прокси-сервера.
const HOST_MASK: Ipv4Addr = Ipv4Addr::new(255, 255, 255, 255);

/// Метрика, устанавливаемая на Wintun-интерфейс, чтобы он стал маршрутом
/// с наивысшим приоритетом (весь трафик идёт через туннель).
const TUNNEL_METRIC: u32 = 1;

/// Метрика маршрута-исключения для прокси-сервера (через реальный шлюз).
const EXCLUSION_METRIC: u32 = 1;

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
        // SAFETY: загружается стандартный подписанный wintun.dll из текущей директории.
        let wintun = unsafe { wintun::load() }.map_err(|e| anyhow!("Не удалось загрузить wintun.dll: {}", e))?;

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

        self.is_active.store(true, Ordering::SeqCst);
        Ok(())
    }

    /// Останавливает сессию и освобождает ресурсы адаптера.
    pub fn deactivate(&self) -> Result<()> {
        let mut guard = self.session.lock().map_err(|e| anyhow!("Не удалось заблокировать сессию: {}", e))?;

        if let Some(wintun_session) = guard.take() {
            wintun_session.session.shutdown();
        }

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

    /// Настраивает таблицу маршрутизации Windows: делает Wintun-интерфейс
    /// маршрутом по умолчанию и добавляет исключение для прокси-сервера,
    /// чтобы избежать петли маршрутизации.
    pub fn configure_routing(&self, proxy_server: Ipv4Addr) -> Result<()> {
        let interface_index = self.get_adapter_index()?;
        let gateway = RouteManager::get_default_gateway()?;

        RouteManager::add_route(proxy_server, HOST_MASK, gateway, EXCLUSION_METRIC)?;
        RouteManager::set_interface_metric(interface_index, TUNNEL_METRIC)?;

        Ok(())
    }

    /// Удаляет маршрут-исключение прокси-сервера, добавленный в [`configure_routing`].
    pub fn restore_routing(&self, proxy_server: Ipv4Addr) -> Result<()> {
        RouteManager::delete_route(proxy_server, HOST_MASK)
    }

    /// Асинхронный цикл чтения пакетов из Wintun. Каждый полученный пакет
    /// учитывается в статистике скорости соединения.
    pub async fn packet_loop(&self, state: Arc<Mutex<VpnState>>) -> Result<()> {
        let session = {
            let guard = self.session.lock().map_err(|e| anyhow!("Не удалось заблокировать сессию: {}", e))?;
            guard
                .as_ref()
                .ok_or_else(|| anyhow!("Сессия Wintun не инициализирована"))?
                .session
                .clone()
        };

        while self.is_active.load(Ordering::SeqCst) {
            let session_clone = session.clone();

            // WintunReceivePacket блокирует поток, поэтому выполняем его в spawn_blocking
            let received = tokio::task::spawn_blocking(move || session_clone.receive_blocking())
                .await
                .map_err(|e| anyhow!("Ошибка задачи чтения пакетов: {}", e))?;

            match received {
                Ok(packet) => {
                    let len = packet.bytes().len() as u64;
                    if let Ok(mut state_guard) = state.lock() {
                        state_guard.speed_bps += len;
                    }
                    // Пакет освобождается автоматически при выходе из области видимости
                }
                Err(_) => {
                    // Сессия завершена через shutdown()
                    break;
                }
            }
        }

        Ok(())
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

pub struct VpnState {
    pub status: crate::VpnStatus,
    pub speed_bps: u64,
    pub current_profile: Option<String>,
}

impl VpnState {
    pub fn new() -> Self {
        Self {
            status: crate::VpnStatus::Disconnected,
            speed_bps: 0,
            current_profile: None,
        }
    }

    pub fn set_status(&mut self, status: crate::VpnStatus) {
        self.status = status;
    }

    pub fn set_speed(&mut self, speed_bps: u64) {
        self.speed_bps = speed_bps;
    }

    pub fn set_profile(&mut self, profile: String) {
        self.current_profile = Some(profile);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

        // Без активации индекс адаптера недоступен
        assert!(adapter.get_adapter_index().is_err());
    }

    #[tokio::test]
    async fn test_packet_loop_without_activation() {
        let state = Arc::new(Mutex::new(VpnState::new()));
        let adapter = WintunAdapter::new("vpn-tun").unwrap();

        // Без активной сессии packet_loop должен вернуть ошибку, а не паниковать
        assert!(adapter.packet_loop(state).await.is_err());
    }

    #[test]
    #[ignore = "требует установленный wintun.dll и права администратора"]
    fn test_wintun_activation() {
        let adapter = WintunAdapter::new("vpn-tun").unwrap();

        adapter.activate().unwrap();
        assert!(adapter.is_active());

        adapter.deactivate().unwrap();
        assert!(!adapter.is_active());
    }

    #[tokio::test]
    #[ignore = "требует установленный wintun.dll и права администратора"]
    async fn test_packet_loop_simulation() {
        let state = Arc::new(Mutex::new(VpnState::new()));
        let adapter = WintunAdapter::new("vpn-tun").unwrap();

        adapter.activate().unwrap();

        tokio::time::timeout(tokio::time::Duration::from_millis(100), adapter.packet_loop(state.clone()))
            .await
            .ok();

        assert!(adapter.is_active());
    }

    #[test]
    #[ignore = "требует установленный wintun.dll и права администратора"]
    fn test_configure_routing() {
        let adapter = WintunAdapter::new("vpn-tun").unwrap();
        adapter.activate().unwrap();

        let proxy_server = Ipv4Addr::new(1, 2, 3, 4);
        adapter.configure_routing(proxy_server).unwrap();
        adapter.restore_routing(proxy_server).unwrap();
    }

    #[test]
    fn test_vpn_state_creation() {
        let state = VpnState::new();
        assert_eq!(state.status, crate::VpnStatus::Disconnected);
        assert_eq!(state.speed_bps, 0);
        assert!(state.current_profile.is_none());
    }

    #[test]
    fn test_vpn_state_status_update() {
        let mut state = VpnState::new();

        state.set_status(crate::VpnStatus::Connecting);
        assert_eq!(state.status, crate::VpnStatus::Connecting);

        state.set_status(crate::VpnStatus::Connected);
        assert_eq!(state.status, crate::VpnStatus::Connected);
    }

    #[test]
    fn test_vpn_state_speed_update() {
        let mut state = VpnState::new();
        state.set_speed(1024 * 1024); // 1 Mbps

        assert_eq!(state.speed_bps, 1024 * 1024);
    }

    #[test]
    fn test_vpn_state_profile_update() {
        let mut state = VpnState::new();

        state.set_profile("vless://user@server.com".to_string());

        assert_eq!(state.current_profile, Some("vless://user@server.com".to_string()));
    }
}
