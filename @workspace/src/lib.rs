# Lib crate for vpn-client VPN proxy application

use std::sync::{Arc, RwLock};

pub mod config;
pub mod state;
pub mod network;
pub mod commands;

/// Структура состояния приложения
#[derive(Clone)]
pub struct AppState {
    pub vpn_state: Arc<RwLock<VpnState>>,
    pub dns_engine: Arc<RwLock<DnsEngine>>,
}

impl AppState {
    /// Создать новое состояние приложения
    pub fn new() -> Self {
        let vpn_state = Arc::new(RwLock::new(VpnState::default()));
        let dns_engine = Arc::new(RwLock::new(DnsEngine::new()));
        
        Self {
            vpn_state,
            dns_engine,
        }
    }

    /// Получить текущий статус VPN
    pub fn get_status(&self) -> VpnStatus {
        self.vpn_state.read().expect("Failed to read status").get_status().expect("Status read failed")
    }

    /// Установить статус VPN
    pub fn set_status(&self, status: VpnStatus) -> Result<(), String> {
        let mut state = self.vpn_state.write().expect("Failed to write status");
        state.set_status(status);
        Ok(())
    }

    /// Записать логи
    pub fn log(&self, level: &str, message: &str) -> Result<(), String> {
        let logs_guard = self.vpn_state.read().expect("Failed to read logs");
        logs_guard.log(level, message)?;
        Ok(())
    }

    /// Получить статистику подключения
    pub fn get_stats(&self) -> state::ConnectionStats {
        let state = self.vpn_state.read().expect("Failed to read stats");
        state.get_stats().expect("Failed to unwrap stats")
    }

    /// Обновить статистику подключения
    pub fn update_stats(&self, ping: u64, download_bps: u64, upload_bps: u64) -> Result<(), String> {
        let mut state = self.vpn_state.write().expect("Failed to write stats");
        state.update_stats(ping, download_bps, upload_bps);
        Ok(())
    }

    /// Получить последнюю запись лога
    pub fn get_latest_log(&self) -> Option<LogEntry> {
        let state = self.vpn_state.read().expect("Failed to read logs");
        state.get_latest_log()
    }

    /// Очистить логи
    pub fn clear_logs(&self) -> Result<(), String> {
        let mut state = self.vpn_state.write().expect("Failed to write logs");
        state.clear_logs()?;
        Ok(())
    }

    /// Получить сфэйковый IP для домена из кэша
    pub fn get_fake_ip(&self, domain: &str) -> Option<String> {
        let state = self.vpn_state.read().expect("Failed to read state");
        state.get_fake_ip(domain)
    }

    /// Добавить запись в кэш сфэйков IP
    pub fn add_fake_ip_entry(
        &self, 
        domain: &str, 
        fake_ip: &str, 
        real_ip: Option<&str>,
    ) -> Result<(), String> {
        let mut state = self.vpn_state.write().expect("Failed to write fake IP cache");
        state.add_fake_ip_entry(domain, fake_ip, real_ip);
        Ok(())
    }

    /// Добавить домен в кэш сфэйков IP
    pub fn add_domain_to_fake_ip_mapping(&self, domain: &str, fake_ip: &str) -> Result<(), String> {
        let mut state = self.vpn_state.write().expect("Failed to write domain map");
        state.add_domain_to_fake_ip_mapping(domain, fake_ip);
        Ok(())
    }

    /// Добавить сфэйковый IP в кэш доменов
    pub fn add_fake_ip_to_domain_mapping(&self, fake_ip: &str, domain: &str) -> Result<(), String> {
        let mut state = self.vpn_state.write().expect("Failed to write fake IP map");
        state.add_fake_ip_to_domain_mapping(fake_ip, domain);
        Ok(())
    }

    /// Получить DNS-движок для разрешения доменов
    pub fn get_dns_engine(&self) -> Arc<RwLock<DnsEngine>> {
        self.dns_engine.clone()
    }

    /// Выделить IP для домена через DNS-движок
    pub async fn allocate_domain_ip(&self, domain: &str) -> Result<String, network::DnsError> {
        let engine = self.dns_engine.read().expect("Failed to read DNS engine");
        Ok(engine.allocate_for_domain(domain).await?)
    }

    /// Освободить IP для домена через DNS-движок
    pub async fn release_domain_ip(&self, domain: &str) -> Result<(), network::DnsError> {
        let engine = self.dns_engine.read().expect("Failed to read DNS engine");
        Ok(engine.release_for_domain(domain).await?)
    }

    /// Проверить наличие домена в кэше
    pub fn has_cached_ip(&self, domain: &str) -> bool {
        let engine = self.dns_engine.read().expect("Failed to read DNS engine");
        engine.has_cached(domain)
    }

    /// Очистить DNS-кэш
    pub async fn clear_dns_cache(&self) -> Result<(), network::DnsError> {
        let mut engine = self.dns_engine.write().expect("Failed to write DNS engine");
        Ok(engine.clear_cache().await?)
    }

    /// Разрешить DNS через DoH (Cloudflare)
    pub async fn resolve_doh(&self, domain: &str) -> Result<String, network::DnsError> {
        let engine = self.dns_engine.read().expect("Failed to read DNS engine");
        Ok(engine.resolve_doh(domain).await?)
    }

    /// Разрешить DNS с маскировкой SNI
    pub async fn resolve_doh_with_sni(&self, domain: &str, sni: &str) -> Result<String, network::DnsError> {
        let engine = self.dns_engine.read().expect("Failed to read DNS engine");
        Ok(engine.resolve_doh_with_sni(domain, sni).await?)
    }

    /// Разрешить DNS с использованием кэша или DoH
    pub async fn resolve(&self, domain: &str) -> Result<String, network::DnsError> {
        let engine = self.dns_engine.read().expect("Failed to read DNS engine");
        Ok(engine.resolve(domain).await?)
    }
}

/// Инициализировать состояние приложения
pub fn init_app_state(_app_handle: tauri::AppHandle) -> AppState {
    let app_state = AppState::new();
    app_state
}