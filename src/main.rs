#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    vpn_client_lib::run();
}
