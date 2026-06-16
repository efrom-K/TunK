#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

pub mod config;
pub mod commands;
pub mod network {
    pub mod dispatch;
    pub mod dns;
    pub mod route;
    pub mod tun;
}

pub mod proxy {
    pub mod connector;
    pub mod obfuscation;
    pub mod reality;
    pub mod sniffer;
    pub mod tls13;
}

pub mod utils;
pub mod state;

pub use state::{VpnStatus, AppState};

use std::sync::Arc;
use commands::{
    add_subscription, get_logs, get_profiles, get_speed_bps, get_vpn_status, set_profile,
    test_profile_connection, toggle_vpn,
};
use tauri::{
    image::Image,
    menu::{Menu, MenuItem, PredefinedMenuItem},
    tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
    Manager,
};

/// Точка входа приложения Tauri. Вызывается из `main.rs`.
pub fn run() {
    tauri::Builder::default()
        .manage(Arc::new(AppState::new()))
        .setup(|app| {
            build_system_tray(app)?;
            let state = app.state::<Arc<AppState>>();
            commands::load_saved_profiles_impl(&**state).ok();
            Ok(())
        })
        // Hide the window instead of closing it — the tray keeps the app alive.
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                api.prevent_close();
                let _ = window.hide();
            }
        })
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
        .expect("error while running Tauri application");
}

/// Returns 32×32 RGBA pixel data for the tray icon:
/// dark-blue background (#163678) with a white "T" glyph.
fn make_tray_icon() -> Vec<u8> {
    let mut rgba = vec![0u8; 32 * 32 * 4];
    for i in (0..rgba.len()).step_by(4) {
        rgba[i] = 22; rgba[i + 1] = 54; rgba[i + 2] = 120; rgba[i + 3] = 255;
    }
    let mut set = |x: usize, y: usize| {
        let i = (y * 32 + x) * 4;
        rgba[i] = 255; rgba[i + 1] = 255; rgba[i + 2] = 255; rgba[i + 3] = 255;
    };
    for x in 5..=26 { for y in 7..=10  { set(x, y); } } // horizontal bar
    for x in 13..=18 { for y in 11..=24 { set(x, y); } } // vertical stem
    rgba
}

/// Builds and registers the system-tray icon with its context menu.
fn build_system_tray(app: &mut tauri::App) -> tauri::Result<()> {
    let show_i      = MenuItem::with_id(app, "show",       "Открыть TunK",  true, None::<&str>)?;
    let connect_i   = MenuItem::with_id(app, "connect",    "Подключить",    true, None::<&str>)?;
    let disconnect_i = MenuItem::with_id(app, "disconnect", "Отключить",    true, None::<&str>)?;
    let sep         = PredefinedMenuItem::separator(app)?;
    let quit_i      = MenuItem::with_id(app, "quit",       "Выход",         true, None::<&str>)?;

    let menu = Menu::with_items(app, &[&show_i, &connect_i, &disconnect_i, &sep, &quit_i])?;
    let icon = Image::new_owned(make_tray_icon(), 32, 32);

    TrayIconBuilder::new()
        .icon(icon)
        .menu(&menu)
        .tooltip("TunK VPN")
        .on_menu_event(|app, event| handle_tray_menu(app, event.id.as_ref()))
        .on_tray_icon_event(|tray, event| {
            // Left click toggles window visibility.
            if let TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                ..
            } = event
            {
                let app = tray.app_handle();
                if let Some(win) = app.get_webview_window("main") {
                    if win.is_visible().unwrap_or(false) {
                        let _ = win.hide();
                    } else {
                        let _ = win.show();
                        let _ = win.set_focus();
                    }
                }
            }
        })
        .build(app)?;

    Ok(())
}

/// Handles tray context menu item clicks.
fn handle_tray_menu(app: &tauri::AppHandle, id: &str) {
    match id {
        "show" => {
            if let Some(win) = app.get_webview_window("main") {
                let _ = win.show();
                let _ = win.set_focus();
            }
        }
        "connect" => {
            let state = (*app.state::<Arc<AppState>>()).clone();
            tokio::spawn(async move {
                if let Err(e) = commands::toggle_vpn_impl(state.clone(), true).await {
                    state.log("ERROR", &format!("Tray: ошибка подключения: {}", e)).ok();
                }
            });
        }
        "disconnect" => {
            let state = (*app.state::<Arc<AppState>>()).clone();
            tokio::spawn(async move {
                if let Err(e) = commands::toggle_vpn_impl(state.clone(), false).await {
                    state.log("ERROR", &format!("Tray: ошибка отключения: {}", e)).ok();
                }
            });
        }
        "quit" => {
            // Graceful shutdown: abort background tasks and deactivate the TUN adapter.
            let state = (*app.state::<Arc<AppState>>()).clone();
            state.abort_background_tasks();
            if let Ok(mut tunnel) = state.tunnel.lock() {
                if let Some(adapter) = tunnel.take() {
                    if let Some(proxy_ip) = state.get_proxy_ip() {
                        let _ = adapter.restore_routing(proxy_ip);
                    }
                    let _ = adapter.deactivate();
                }
            }
            std::process::exit(0);
        }
        _ => {}
    }
}
