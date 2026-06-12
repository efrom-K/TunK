#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]


pub mod config;
pub mod commands;
pub mod network {
    pub mod dns;
    pub mod route;
    pub mod tun;
}

pub mod proxy {
    pub mod obfuscation;
    pub mod sniffer;
}

pub mod utils;
pub mod state;

// Экспортируем типы из state для использования в других модулях
pub use state::{VpnStatus, AppState};
