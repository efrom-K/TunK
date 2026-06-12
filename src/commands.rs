use crate::{AppState, VpnStatus};
use tauri::State;
use anyhow::Result as AnyResult;


#[tauri::command]
async fn toggle_vpn(state: State<'_, AppState>, _enable: bool) -> AnyResult<(), String> {
    let _ = state.set_status(VpnStatus::Connecting);
    // TODO: Real connection logic
    let _ = state.set_status(VpnStatus::Connected);
    Ok(())
}

#[tauri::command]
async fn add_subscription(_state: State<'_, AppState>, url: String) -> AnyResult<Vec<String>, String> {
    // TODO: Real subscription logic
    Ok(vec![url])
}

#[tauri::command]
async fn get_vpn_status(state: State<'_, AppState>) -> AnyResult<VpnStatus, String> {
    let _ = state.get_status();
    Ok(VpnStatus::Disconnected)
}

#[tauri::command]
async fn get_speed_bps(_state: State<'_, AppState>) -> AnyResult<u64, String> {
    Ok(0)
}

fn parse_subscription(url: &str) -> AnyResult<Vec<String>, String> {
    let mut profiles = Vec::new();
    if url.starts_with("vles://") || url.starts_with("ss://") {
        profiles.push(url.to_string());
    } else {
        return Err(format!("Неподдерживаемый формат подписки: {}", url));
    }
    Ok(profiles)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_subscription_vles() {
        let result = parse_subscription("vles://user@server.com");
        assert!(result.is_ok());
    }

    #[test]
    fn test_parse_subscription_ss() {
        let result = parse_subscription("ss://base64data@server.com");
        assert!(result.is_ok());
    }

    #[test]
    fn test_parse_subscription_invalid() {
        let result = parse_subscription("invalid://url");
        assert!(result.is_err());
    }
}