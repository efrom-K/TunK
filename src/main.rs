#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::sync::{Arc, Mutex};
use tauri::State;
use anyhow::Result;

mod commands;
mod config;
mod network {
    pub mod dns;
    pub mod tun;
}
mod proxy {
    pub mod obfuscation;
    pub mod sniffer;
}
mod utils;

#[derive(Debug, Clone)]
pub enum VpnStatus {
    Disconnected,
    Connecting,
    Connected,
    Disconnecting,
}

#[tauri::command]
async fn toggle_vpn(state: State<AppState>, enable: bool) -> Result<(), String> {
    let current_status = state.status.clone();
    
    if enable {
        match &current_status {
            VpnStatus::Disconnected | VpnStatus::Disconnecting => {
                state.set_status(VpnStatus::Connecting);
                
                // Здесь будет логика подключения:
                // 1. Запуск Wintun адаптера
                // 2. Настройка маршрутизации Windows
                // 3. Подключение к прокси-серверу
                
                Ok(())
            }
            _ => Err("VPN уже подключен".to_string()),
        }
    } else {
        match &current_status {
            VpnStatus::Connected | VpnStatus::Connecting => {
                state.set_status(VpnStatus::Disconnecting);
                
                // Здесь будет логика отключения:
                // 1. Отключение прокси-соединения
                // 2. Сброс маршрутизации Windows
                
                Ok(())
            }
            _ => Err("VPN не подключен".to_string()),
        }
    }
}

#[tauri::command]
async fn add_subscription(state: State<AppState>, url: String) -> Result<Vec<String>, String> {
    // Здесь будет логика добавления подписки
    Ok(vec![])
}

#[derive(Debug, Default)]
pub struct AppState {
    pub status: VpnStatus,
    pub speed_bps: u64,
    pub current_profile: Option<String>,
}

impl AppState {
    pub fn new() -> Self {
        Self {
            status: VpnStatus::Disconnected,
            speed_bps: 0,
            current_profile: None,
        }
    }

    pub fn set_status(&mut self, status: VpnStatus) {
        self.status = status;
    }

    pub fn set_speed(&mut self, speed_bps: u64) {
        self.speed_bps = speed_bps;
    }

    pub fn set_profile(&mut self, profile: String) {
        self.current_profile = Some(profile);
    }
}

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_window_state::Builder::new().build())
        .manage(AppState::new())
        .invoke_handler(tauri::generate_handler![toggle_vpn, add_subscription])
        .setup(|app| {
            // Инициализация TrayIcon
            let window = app.get_window("main").unwrap();
            
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("Error while running Tauri application");
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
