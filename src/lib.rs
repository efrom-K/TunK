pub mod config;
pub mod commands;
pub mod network {
    pub mod dns;
    pub mod tun;
}
pub mod proxy {
    pub mod obfuscation;
    pub mod sniffer;
}
pub mod utils;

use tauri::State;
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone)]
pub enum VpnStatus {
    Disconnected,
    Connecting,
    Connected,
    Disconnecting,
}

#[derive(Debug, Default, Clone)]
pub struct AppState {
    pub status: VpnStatus,
    pub speed_bps: u64,
    pub current_profile: Option<String>,
    pub fake_ip_cache: Arc<Mutex<std::collections::HashMap<String, String>>>,
}

impl AppState {
    pub fn new() -> Self {
        Self {
            status: VpnStatus::Disconnected,
            speed_bps: 0,
            current_profile: None,
            fake_ip_cache: Arc::new(Mutex::new(std::collections::HashMap::new())),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_app_state_creation() {
        let state = AppState::new();
        assert_eq!(state.status, VpnStatus::Disconnected);
        assert_eq!(state.speed_bps, 0);
        assert!(state.current_profile.is_none());
    }

    #[tokio::test]
    async fn test_status_transitions() {
        let mut state = AppState::new();
        
        state.set_status(VpnStatus::Connecting);
        assert_eq!(state.status, VpnStatus::Connecting);
        
        state.set_status(VpnStatus::Connected);
        assert_eq!(state.status, VpnStatus::Connected);
    }

    #[test]
    fn test_speed_update() {
        let mut state = AppState::new();
        state.set_speed(1024 * 1024); // 1 Mbps
        assert_eq!(state.speed_bps, 1024 * 1024);
    }
}
