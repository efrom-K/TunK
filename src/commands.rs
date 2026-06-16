use std::net::Ipv4Addr;
use std::sync::Arc;

use crate::config::{parse_subscription_url, ProxyProfile};
use crate::network::dispatch;
use crate::network::dns::DnsProxy;
use crate::network::tun::WintunAdapter;
use crate::proxy::connector::ProxyConnector;
use crate::state::LogEntry;
use crate::{AppState, VpnStatus};
use tauri::State;

const TUN_INTERFACE_NAME: &str = "vpn-tun";
const DNS_BIND_ADDR: &str = "127.0.0.1:53";

/// Включает или отключает VPN-туннель и возвращает итоговый статус.
#[tauri::command]
pub async fn toggle_vpn(state: State<'_, Arc<AppState>>, enable: bool) -> Result<VpnStatus, String> {
    toggle_vpn_impl((*state).clone(), enable).await
}

pub(crate) async fn toggle_vpn_impl(state: Arc<AppState>, enable: bool) -> Result<VpnStatus, String> {
    if enable {
        let profile_id = state.get_profile_id().ok_or("Профиль не выбран")?;
        let profile = state
            .find_profile(&profile_id)?
            .ok_or_else(|| format!("Профиль {} не найден", profile_id))?;

        state.set_status(VpnStatus::Connecting);
        state.log("INFO", "Подключение к серверу...")?;

        // 1. Create and activate the Wintun adapter.
        let adapter = WintunAdapter::new(TUN_INTERFACE_NAME).map_err(|e| e.to_string())?;
        if let Err(e) = adapter.activate() {
            state.set_status(VpnStatus::Disconnected);
            state.log("ERROR", &format!("Ошибка активации Wintun: {}", e))?;
            return Err(e.to_string());
        }

        // 2. Extract Arc<Session> before moving the adapter into state.tunnel.
        let session = adapter.get_session().map_err(|e| e.to_string())?;

        // 3. Resolve proxy server IP for the routing exclusion route (best-effort).
        let proxy_ip = resolve_host_ipv4(&profile.server, profile.port).await;
        if let Some(ip) = proxy_ip {
            match adapter.configure_routing(ip) {
                Ok(()) => state.log("INFO", &format!("Маршрутизация настроена, исключение: {}", ip))?,
                Err(e) => state.log("WARN", &format!("Не удалось настроить маршрутизацию: {}", e))?,
            }
            state.set_proxy_ip(Some(ip));
        } else {
            state.log(
                "WARN",
                &format!(
                    "Не удалось определить IP для {}, маршрутизация без исключения прокси",
                    profile.server
                ),
            )?;
        }

        // 4. Store adapter so deactivate() can be called on disconnect.
        {
            let mut tunnel = state.tunnel.lock().map_err(|e| e.to_string())?;
            *tunnel = Some(adapter);
        }

        // 5. Spawn DNS proxy task (127.0.0.1:53).
        let dns_state = state.clone();
        let dns_handle = tokio::spawn(async move {
            match DnsProxy::new(DNS_BIND_ADDR.parse().unwrap())
                .run(dns_state.clone(), None)
                .await
            {
                Ok(()) => {}
                Err(e) => {
                    dns_state
                        .log("ERROR", &format!("DNS proxy остановлен: {}", e))
                        .ok();
                }
            }
        });
        state.register_task_handle(dns_handle.abort_handle());

        // 6. Spawn packet dispatch loop task.
        let dispatch_state = state.clone();
        let dispatch_handle = tokio::spawn(async move {
            if let Err(e) = dispatch::run_dispatch(session, dispatch_state.clone()).await {
                dispatch_state
                    .log("INFO", &format!("Dispatch loop остановлен: {}", e))
                    .ok();
            }
        });
        state.register_task_handle(dispatch_handle.abort_handle());

        state.set_status(VpnStatus::Connected);
        state.log("INFO", "VPN активен")?;
    } else {
        state.set_status(VpnStatus::Disconnecting);
        state.log("INFO", "Отключение...")?;

        // Abort DNS proxy + dispatch loop.
        state.abort_background_tasks();

        // Deactivate Wintun adapter and restore the routing exclusion.
        let mut tunnel = state.tunnel.lock().map_err(|e| e.to_string())?;
        if let Some(adapter) = tunnel.take() {
            if let Some(proxy_ip) = state.get_proxy_ip() {
                if let Err(e) = adapter.restore_routing(proxy_ip) {
                    state
                        .log("WARN", &format!("Не удалось восстановить маршрутизацию: {}", e))
                        .ok();
                }
            }
            adapter.deactivate().map_err(|e| e.to_string())?;
        }
        drop(tunnel);

        state.set_proxy_ip(None);
        state.clear_cache()?;
        state.set_status(VpnStatus::Disconnected);
        state.log("INFO", "Отключено")?;
    }

    state.get_status()
}

/// Resolves a hostname/IP string to its first IPv4 address.
/// Tries direct parse first, then falls back to the system DNS resolver.
async fn resolve_host_ipv4(host: &str, port: u16) -> Option<Ipv4Addr> {
    if let Ok(ip) = host.parse::<Ipv4Addr>() {
        return Some(ip);
    }
    tokio::net::lookup_host(format!("{}:{}", host, port))
        .await
        .ok()?
        .find_map(|addr| match addr.ip() {
            std::net::IpAddr::V4(ip) => Some(ip),
            _ => None,
        })
}

/// Разбирает текст подписки (одна или несколько ссылок, по одной на строку)
/// и сохраняет полученные профили в состоянии приложения.
#[tauri::command]
pub async fn add_subscription(
    state: State<'_, Arc<AppState>>,
    url: String,
) -> Result<Vec<ProxyProfile>, String> {
    add_subscription_impl(&**state, &url)
}

fn add_subscription_impl(state: &AppState, url: &str) -> Result<Vec<ProxyProfile>, String> {
    let mut profiles = Vec::new();

    for line in url.lines().map(str::trim).filter(|line| !line.is_empty()) {
        profiles.push(parse_subscription_url(line)?);
    }

    if profiles.is_empty() {
        return Err("Подписка не содержит ни одного валидного URL".to_string());
    }

    state.set_profiles(profiles.clone())?;
    Ok(profiles)
}

/// Возвращает текущий статус VPN-подключения.
#[tauri::command]
pub async fn get_vpn_status(state: State<'_, Arc<AppState>>) -> Result<VpnStatus, String> {
    state.get_status()
}

/// Возвращает суммарную скорость соединения (download + upload) в битах в секунду.
#[tauri::command]
pub async fn get_speed_bps(state: State<'_, Arc<AppState>>) -> Result<u64, String> {
    let stats = state.get_stats()?;
    Ok(stats.download_speed_bps + stats.upload_speed_bps)
}

/// Выбирает профиль для подключения по его идентификатору.
#[tauri::command]
pub async fn set_profile(
    state: State<'_, Arc<AppState>>,
    profile_id: String,
) -> Result<(), String> {
    set_profile_impl(&**state, &profile_id)
}

fn set_profile_impl(state: &AppState, profile_id: &str) -> Result<(), String> {
    state
        .find_profile(profile_id)?
        .ok_or_else(|| format!("Профиль {} не найден", profile_id))?;
    state.set_profile_id(Some(profile_id.to_string()));
    Ok(())
}

/// Возвращает список доступных профилей.
#[tauri::command]
pub async fn get_profiles(state: State<'_, Arc<AppState>>) -> Result<Vec<ProxyProfile>, String> {
    state.get_profiles()
}

/// Возвращает накопленный журнал событий.
#[tauri::command]
pub async fn get_logs(state: State<'_, Arc<AppState>>) -> Result<Vec<LogEntry>, String> {
    state.get_logs()
}

/// Проверяет соединение с сервером профиля: открывает TCP-соединение,
/// выполняет хендшейк протокола и измеряет задержку. Результат
/// сохраняется в `ConnectionStats.ping`.
#[tauri::command]
pub async fn test_profile_connection(
    state: State<'_, Arc<AppState>>,
    profile_id: String,
) -> Result<u64, String> {
    test_profile_connection_impl(&**state, &profile_id).await
}

async fn test_profile_connection_impl(state: &AppState, profile_id: &str) -> Result<u64, String> {
    let profile = state
        .find_profile(profile_id)?
        .ok_or_else(|| format!("Профиль {} не найден", profile_id))?;

    let ping = ProxyConnector::measure_latency(&profile)
        .await
        .map_err(|e| e.to_string())?;

    let stats = state.get_stats()?;
    state.update_stats(ping, stats.download_speed_bps, stats.upload_speed_bps)?;
    Ok(ping)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vless_url() -> &'static str {
        "vless://550e8400-e29b-41d4-a716-446655440000@example.com:443#Test"
    }

    #[test]
    fn test_get_vpn_status_default() {
        let state = AppState::new();
        assert_eq!(state.get_status().unwrap(), VpnStatus::Disconnected);
    }

    #[test]
    fn test_get_speed_bps_default() {
        let state = AppState::new();
        let stats = state.get_stats().unwrap();
        assert_eq!(stats.download_speed_bps + stats.upload_speed_bps, 0);
    }

    #[test]
    fn test_add_subscription_valid() {
        let state = AppState::new();
        let profiles = add_subscription_impl(&state, vless_url()).unwrap();
        assert_eq!(profiles.len(), 1);
        assert_eq!(profiles[0].server, "example.com");
        assert_eq!(state.get_profiles().unwrap().len(), 1);
    }

    #[test]
    fn test_add_subscription_invalid() {
        let state = AppState::new();
        let result = add_subscription_impl(&state, "http://example.com");
        assert!(result.is_err());
    }

    #[test]
    fn test_set_profile_unknown() {
        let state = AppState::new();
        let result = set_profile_impl(&state, "missing");
        assert!(result.is_err());
    }

    #[test]
    fn test_set_profile_known() {
        let state = AppState::new();
        let profiles = add_subscription_impl(&state, vless_url()).unwrap();
        let profile_id = profiles[0].id.clone();
        set_profile_impl(&state, &profile_id).unwrap();
        assert_eq!(state.get_profile_id(), Some(profile_id));
    }

    #[test]
    fn test_get_profiles_empty_then_populated() {
        let state = AppState::new();
        assert!(state.get_profiles().unwrap().is_empty());
        add_subscription_impl(&state, vless_url()).unwrap();
        assert_eq!(state.get_profiles().unwrap().len(), 1);
    }

    #[test]
    fn test_get_logs() {
        let state = AppState::new();
        state.log("INFO", "test message").unwrap();
        let logs = state.get_logs().unwrap();
        assert_eq!(logs.len(), 1);
        assert_eq!(logs[0].message, "test message");
    }

    #[tokio::test]
    async fn test_toggle_vpn_without_profile() {
        let state = Arc::new(AppState::new());
        let result = toggle_vpn_impl(state.clone(), true).await;
        assert!(result.is_err());
        assert_eq!(state.get_status().unwrap(), VpnStatus::Disconnected);
    }

    #[tokio::test]
    async fn test_toggle_vpn_disable_when_idle() {
        let state = Arc::new(AppState::new());
        let status = toggle_vpn_impl(state, false).await.unwrap();
        assert_eq!(status, VpnStatus::Disconnected);
    }

    #[tokio::test]
    #[ignore = "требует установленный wintun.dll и права администратора"]
    async fn test_toggle_vpn_enable_with_profile() {
        let state = Arc::new(AppState::new());
        let profiles = add_subscription_impl(&state, vless_url()).unwrap();
        set_profile_impl(&state, &profiles[0].id).unwrap();
        let status = toggle_vpn_impl(state, true).await.unwrap();
        assert_eq!(status, VpnStatus::Connected);
    }

    #[tokio::test]
    async fn test_resolve_host_ipv4_direct() {
        let ip = resolve_host_ipv4("1.2.3.4", 443).await;
        assert_eq!(ip, Some(Ipv4Addr::new(1, 2, 3, 4)));
    }

    #[tokio::test]
    async fn test_resolve_host_ipv4_ipv6_address_is_skipped() {
        // Passing a raw IPv6 address should not parse as Ipv4Addr.
        // lookup_host may still resolve it but we only return IPv4.
        let ip = resolve_host_ipv4("::1", 80).await;
        // ::1 is IPv6 only — expect None (no IPv4 result)
        assert!(ip.is_none());
    }

    #[tokio::test]
    async fn test_profile_connection_unknown_profile() {
        let state = AppState::new();
        let result = test_profile_connection_impl(&state, "missing").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    #[ignore = "требует рабочую подписку с реальным сервером и доступ в сеть"]
    async fn test_profile_connection_real_server() {
        let state = AppState::new();
        let profiles = add_subscription_impl(&state, vless_url()).unwrap();
        let profile_id = profiles[0].id.clone();
        let ping = test_profile_connection_impl(&state, &profile_id).await.unwrap();
        assert!(ping == 0 || ping > 0);
        assert_eq!(state.get_stats().unwrap().ping, ping);
    }
}
