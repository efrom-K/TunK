// Bin crate для vpn-client - инициализация Tauri приложения
#![cfg_attr(
    all(not(debug_assertions), target_os = "windows"),
    windows_subsystem = "windows"
)]

use std::sync::{Arc, RwLock};
use crate::lib::AppState;

fn main() {
    let app_state = AppState::new();
    
    tauri::Builder::default()
        .manage(app_state)
        .invoke_handler(tauri::generate_handler![
            toggle_vpn,
            add_subscription,
            get_status
        ])
        .setup(|app| {
            // Создаем треевский икону
            let app_handle = app.handle().clone();
            
            if std::path::Path::new("icons/icon.ico").exists() {
                let tray = tauri::menu::TrayBuilder::new(
                    tauri::Icon::default_icon(),
                    "tray-icon".to_string()
                )
                .build();

                app.handle().app_menu().add_native_app_menu_item(tauri::menu::MenuItem::new(
                    &format!("{}: Show Window", app.package_info().name),
                    "show-window",
                    false,
                ))?
                .show_window(app.handle())?;

                let menu_id = app.handle().app_menu().add_native_app_menu_item(
                    tauri::menu::MenuItem::new("Hide", "hide", false)
                )?.id();

                app_handle.listen_global(menu_id, move |_e| {
                    if let Some(window) = app.get_window("main") {
                        window.minimize();
                    }
                });

                app.handle()
                    .build_tray(tray)
                    .unwrap();
            } else {
                eprintln!("TunK icon not found");
            }

            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}