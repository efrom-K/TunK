use crate::config::{parse_subscription_url, ProxyProfile};
use crate::network::tun::WintunAdapter;
use crate::proxy::connector::ProxyConnector;
use crate::state::LogEntry;
use crate::{AppState, VpnStatus};
use tauri::State;

/// Имя Wintun-интерфейса, используемого этим приложением.
const TUN_INTERFACE_NAME: &str = "vpn-tun";

/// Включает или отключает VPN-туннель и возвращает итоговый статус подключения.
#[tauri::command]
pub async fn toggle_vpn(state: State<'_, AppState>, enable: bool) -> Result<VpnStatus, String> {
    toggle_vpn_impl(&state, enable)
}

fn toggle_vpn_impl(state: &AppState, enable: bool) -> Result<VpnStatus, String> {
    if enable {
        let profile_id = state
            .get_profile_id()
            .ok_or_else(|| "Профиль не выбран".to_string())?;

        state
            .find_profile(&profile_id)?
            .ok_or_else(|| format!("Профиль {} не найден", profile_id))?;

        state.set_status(VpnStatus::Connecting);
        state.log("INFO", "Подключение к серверу...")?;

        let adapter = WintunAdapter::new(TUN_INTERFACE_NAME).map_err(|e| e.to_string())?;

        if let Err(e) = adapter.activate() {
            state.set_status(VpnStatus::Disconnected);
            state.log("ERROR", &format!("Ошибка активации Wintun: {}", e))?;
            return Err(e.to_string());
        }

        let mut tunnel = state.tunnel.lock().map_err(|e| e.to_string())?;
        *tunnel = Some(adapter);
        drop(tunnel);

        state.set_status(VpnStatus::Connected);
        state.log("INFO", "Подключено")?;
    } else {
        state.set_status(VpnStatus::Disconnecting);

        let mut tunnel = state.tunnel.lock().map_err(|e| e.to_string())?;
        if let Some(adapter) = tunnel.take() {
            adapter.deactivate().map_err(|e| e.to_string())?;
        }
        drop(tunnel);

        state.set_status(VpnStatus::Disconnected);
        state.log("INFO", "Отключено")?;
    }

    state.get_status()
}

/// Разбирает текст подписки (одна или несколько ссылок на сервер, по одной на строку)
/// и сохраняет полученные профили в состоянии приложения.
#[tauri::command]
pub async fn add_subscription(state: State<'_, AppState>, url: String) -> Result<Vec<ProxyProfile>, String> {
    add_subscription_impl(&state, &url)
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
pub async fn get_vpn_status(state: State<'_, AppState>) -> Result<VpnStatus, String> {
    state.get_status()
}

/// Возвращает суммарную скорость соединения (download + upload) в битах в секунду.
#[tauri::command]
pub async fn get_speed_bps(state: State<'_, AppState>) -> Result<u64, String> {
    let stats = state.get_stats()?;
    Ok(stats.download_speed_bps + stats.upload_speed_bps)
}

/// Выбирает профиль для подключения по его идентификатору.
#[tauri::command]
pub async fn set_profile(state: State<'_, AppState>, profile_id: String) -> Result<(), String> {
    set_profile_impl(&state, &profile_id)
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
pub async fn get_profiles(state: State<'_, AppState>) -> Result<Vec<ProxyProfile>, String> {
    state.get_profiles()
}

/// Возвращает накопленный журнал событий (FAKEIP-сниффер, статус и т.д.).
#[tauri::command]
pub async fn get_logs(state: State<'_, AppState>) -> Result<Vec<LogEntry>, String> {
    state.get_logs()
}

/// Проверяет соединение с сервером профиля: открывает TCP-соединение,
/// выполняет хендшейк протокола (VLESS/Shadowsocks/Trojan) и измеряет
/// задержку. Результат сохраняется в `ConnectionStats.ping`.
#[tauri::command]
pub async fn test_profile_connection(state: State<'_, AppState>, profile_id: String) -> Result<u64, String> {
    test_profile_connection_impl(&state, &profile_id).await
}

async fn test_profile_connection_impl(state: &AppState, profile_id: &str) -> Result<u64, String> {
    let profile = state
        .find_profile(profile_id)?
        .ok_or_else(|| format!("Профиль {} не найден", profile_id))?;

    let ping = ProxyConnector::measure_latency(&profile).await.map_err(|e| e.to_string())?;

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

    #[test]
    fn test_toggle_vpn_without_profile() {
        let state = AppState::new();

        let result = toggle_vpn_impl(&state, true);

        assert!(result.is_err());
        assert_eq!(state.get_status().unwrap(), VpnStatus::Disconnected);
    }

    #[test]
    fn test_toggle_vpn_disable_when_idle() {
        let state = AppState::new();

        let status = toggle_vpn_impl(&state, false).unwrap();

        assert_eq!(status, VpnStatus::Disconnected);
    }

    #[test]
    #[ignore = "требует установленный wintun.dll и права администратора"]
    fn test_toggle_vpn_enable_with_profile() {
        let state = AppState::new();

        let profiles = add_subscription_impl(&state, vless_url()).unwrap();
        set_profile_impl(&state, &profiles[0].id).unwrap();

        let status = toggle_vpn_impl(&state, true).unwrap();

        assert_eq!(status, VpnStatus::Connected);
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

        assert!(ping > 0 || ping == 0);
        assert_eq!(state.get_stats().unwrap().ping, ping);
    }
}
