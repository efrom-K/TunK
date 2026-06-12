#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use tauri::{Manager, State};
use anyhow::Result;

mod commands;
mod config;
mod network {
    pub mod dns;
    pub mod route;
    pub mod tun;
}
mod proxy {
    pub mod obfuscation;
    pub mod sniffer;
}
mod utils;

#[tauri::command]
async fn toggle_vpn(state: State<'_, AppState>, enable: bool) -> Result<(), String> {
    if enable {
        // Здесь будет логика подключения VPN
        Ok(())
    } else {
        // Здесь будет логика отключения VPN
        Ok(())
    }
}

#[tauri::command]
async fn add_subscription(_state: State<'_, AppState>, _url: String) -> Result<Vec<String>, String> {
    // Здесь будет логика добавления подписки
    Ok(vec![])
}

fn main() {
    tauri::Builder::default()
        .manage(AppState::new())
        .invoke_handler(tauri::generate_handler![toggle_vpn, add_subscription])
        .build()
        .expect("Error while running Tauri application")
        .run(tauri::generate_context!());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vpn_status_enum() {
        let status = VpnStatus::Disconnected;
        assert_eq!(status, VpnStatus::Disconnected);
        
        let status = VpnStatus::Connecting;
        assert_eq!(status, VpnStatus::Connecting);
        
        let status = VpnStatus::Connected;
        assert_eq!(status, VpnStatus::Connected);
    }

    #[test]
    fn test_app_state_creation() {
        let state = AppState::new();
        assert_eq!(state.status, VpnStatus::Disconnected);
        assert_eq!(state.speed_bps, 0);
        assert!(state.current_profile.is_none());
    }
}