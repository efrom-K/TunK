#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]


pub mod config;
pub mod commands;
pub mod network {
    pub mod dns;
    pub mod route;
    pub mod tun;
}

pub mod proxy {
    pub mod connector;
    pub mod obfuscation;
    pub mod sniffer;
}

pub mod utils;
pub mod state;

// Экспортируем типы из state для использования в других модулях
pub use state::{VpnStatus, AppState};

use commands::{
    add_subscription, get_logs, get_profiles, get_speed_bps, get_vpn_status, set_profile, test_profile_connection,
    toggle_vpn,
};

/// Точка входа приложения Tauri. Вызывается из `main.rs`.
///
/// `tauri::generate_handler!` должен находиться в той же crate, что и
/// функции `#[tauri::command]`, поэтому регистрация хендлеров живёт здесь,
/// а `main.rs` остаётся тонкой оберткой.
pub fn run() {
    tauri::Builder::default()
        .manage(AppState::new())
        .invoke_handler(tauri::generate_handler![
            toggle_vpn,
            add_subscription,
            get_vpn_status,
            get_speed_bps,
            set_profile,
            get_profiles,
            get_logs,
            test_profile_connection,
        ])
        .run(tauri::generate_context!())
        .expect("Error while running Tauri application");
}
