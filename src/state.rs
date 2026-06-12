use dashmap::DashMap;
use std::sync::{Arc, Mutex, RwLock};
use chrono;

#[derive(Debug, Clone, PartialEq)]
pub enum VpnStatus {
    Disconnected,
    Connecting,
    Connected,
    Disconnecting,
}

impl Default for VpnStatus {
    fn default() -> Self {
        Self::Disconnected
    }
}

#[derive(Debug, Clone)]
pub struct ConnectionStats {
    pub ping: u64,
    pub download_speed_bps: u64,
    pub upload_speed_bps: u64,
}

impl Default for ConnectionStats {
    fn default() -> Self {
        Self {
            ping: 0,
            download_speed_bps: 0,
            upload_speed_bps: 0,
        }
    }
}

#[derive(Debug)]
pub struct FakeIpCacheEntry {
    pub domain: String,
    pub fake_ip: String,
    pub real_ip: Option<String>,
}

impl Default for FakeIpCacheEntry {
    fn default() -> Self {
        Self {
            domain: String::new(),
            fake_ip: String::new(),
            real_ip: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct LogEntry {
    pub timestamp: String,
    pub level: String,
    pub message: String,
}

impl Default for LogEntry {
    fn default() -> Self {
        Self {
            timestamp: String::new(),
            level: "INFO".to_string(),
            message: String::new(),
        }
    }
}

/// Структура для сохранения состояния Tauri приложения
pub struct AppState {
    pub status: RwLock<VpnStatus>,
    pub stats: RwLock<ConnectionStats>,
    pub fake_ip_cache: DashMap<String, FakeIpCacheEntry>,
    pub domain_to_fake_ip: DashMap<String, String>,
    pub fake_ip_to_domain: DashMap<String, String>,
    pub logs: Arc<Mutex<Vec<LogEntry>>>,
    #[allow(dead_code)]
    pub profile_id: RwLock<Option<String>>,
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            status: RwLock::new(VpnStatus::Disconnected),
            stats: RwLock::new(ConnectionStats::default()),
            fake_ip_cache: DashMap::new(),
            domain_to_fake_ip: DashMap::new(),
            fake_ip_to_domain: DashMap::new(),
            logs: Arc::new(Mutex::new(Vec::new())),
            profile_id: RwLock::new(None),
        }
    }
}

impl AppState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Логирование события с сохранением в памяти
    pub fn log(&self, level: &str, message: &str) -> Result<(), String> {
        let timestamp = chrono::Local::now().format("%H:%M:%S").to_string();

        let mut logs = self.logs.lock().map_err(|e| e.to_string())?;
        logs.push(LogEntry {
            timestamp,
            level: level.to_string(),
            message: message.to_string(),
        });

        if logs.len() > 100 {
            logs.remove(0);
        }

        Ok(())
    }

    /// Получение последнего лога
    pub fn get_latest_log(&self) -> Option<LogEntry> {
        let logs = self.logs.lock().ok()?;
        logs.last().cloned()
    }

    /// Очистка всех логов
    pub fn clear_logs(&self) -> Result<(), String> {
        let mut logs = self.logs.lock().map_err(|e| e.to_string())?;
        logs.clear();
        Ok(())
    }

    /// Установка статуса подключения
    pub fn set_status(&self, status: VpnStatus) {
        if let Ok(mut guard) = self.status.write() {
            *guard = status;
        }
    }

    /// Получение текущего статуса подключения
    pub fn get_status(&self) -> Result<VpnStatus, String> {
        self.status
            .read()
            .map(|guard| guard.clone())
            .map_err(|e| e.to_string())
    }

    /// Обновление статистики соединения
    pub fn update_stats(&self, ping: u64, download_bps: u64, upload_bps: u64) -> Result<(), String> {
        let mut stats = self.stats.write().map_err(|e| e.to_string())?;
        stats.ping = ping;
        stats.download_speed_bps = download_bps;
        stats.upload_speed_bps = upload_bps;
        Ok(())
    }

    /// Получение текущей статистики
    pub fn get_stats(&self) -> Result<ConnectionStats, String> {
        Ok(self.stats.read().map_err(|e| format!("Failed to read stats: {}", e))?.clone())
    }

    /// Добавление записи в кэш FakeIP
    pub fn add_fake_ip_entry(&self, domain: &str, fake_ip: &str, real_ip: Option<&str>) {
        let entry = FakeIpCacheEntry {
            domain: domain.to_string(),
            fake_ip: fake_ip.to_string(),
            real_ip: real_ip.map(|s| s.to_string()),
        };

        self.fake_ip_cache.insert(domain.to_string(), entry);
    }

    /// Получение FakeIP для домена
    pub fn get_fake_ip(&self, domain: &str) -> Option<String> {
        if let Some(ip) = self.domain_to_fake_ip.get(domain) {
            return Some(ip.clone());
        }
        self.fake_ip_cache.get(domain).map(|e| e.fake_ip.clone())
    }

    /// Добавление сопоставления домен -> FakeIP в мейнпуджет
    pub fn add_domain_to_fake_ip_mapping(&self, domain: &str, fake_ip: &str) {
        self.domain_to_fake_ip.insert(domain.to_string(), fake_ip.to_string());
    }

    /// Добавление сопоставления FakeIP -> домен в мейнпуджет
    pub fn add_fake_ip_to_domain_mapping(&self, fake_ip: &str, domain: &str) {
        self.fake_ip_to_domain.insert(fake_ip.to_string(), domain.to_string());
    }

    /// Очистка кэша доменов и FakeIP
    pub fn clear_cache(&self) -> Result<(), String> {
        let _ = self.domain_to_fake_ip.clear();
        let _ = self.fake_ip_to_domain.clear();
        Ok(())
    }

    /// Очистка кэша доменов и FakeIP (через AppState)
    pub fn clear_vpn_cache(&self) -> Result<(), String> {
        self.clear_cache()
    }

    /// Проверка наличия домена в кэше
    pub fn has_cached_domain(&self, domain: &str) -> bool {
        self.domain_to_fake_ip.contains_key(domain)
    }

    /// Проверка наличия домена в кэше (через AppState)
    pub fn has_cached_domain_vpn(&self, domain: &str) -> bool {
        self.domain_to_fake_ip.contains_key(domain)
    }

    /// Установка профиля
    pub fn set_profile_id(&self, profile_id: Option<String>) {
        if let Ok(mut guard) = self.profile_id.write() {
            *guard = profile_id;
        }
    }

    /// Получение текущего профиля
    pub fn get_profile_id(&self) -> Option<String> {
        match self.profile_id.read() {
            Ok(guard) => guard.clone(),
            Err(_) => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_app_state_initialization() {
        let state = AppState::new();
        
        assert_eq!(state.get_status().unwrap(), VpnStatus::Disconnected);
        assert_eq!(state.get_stats().unwrap().ping, 0);
        assert!(state.fake_ip_cache.is_empty());
    }

    #[test]
    fn test_log_functionality() {
        let state = AppState::new();
        
        state.log("INFO", "Test message").unwrap();
        
        let latest = state.get_latest_log().unwrap();
        assert_eq!(latest.level, "INFO");
        assert_eq!(latest.message, "Test message");
    }

    #[test]
    fn test_status_change() {
        let state = AppState::new();
        
        state.set_status(VpnStatus::Connecting);
        assert_eq!(state.get_status().unwrap(), VpnStatus::Connecting);

        state.set_status(VpnStatus::Connected);
        assert_eq!(state.get_status().unwrap(), VpnStatus::Connected);
    }

    #[test]
    fn test_stats_update() {
        let state = AppState::new();
        
        state.update_stats(50, 1000000, 500000).unwrap();
        
        let stats = state.get_stats().unwrap();
        assert_eq!(stats.ping, 50);
        assert_eq!(stats.download_speed_bps, 1000000);
        assert_eq!(stats.upload_speed_bps, 500000);
    }

    #[test]
    fn test_log_limit() {
        let state = AppState::new();
        
        for i in 0..105 {
            state.log("INFO", &format!("Log message {}", i)).unwrap();
        }
        
        assert_eq!(state.logs.lock().unwrap().len(), 100);
    }

    #[tokio::test]
    async fn test_concurrent_log_access() {
        let state = Arc::new(AppState::new());

        let mut handles = Vec::new();

        for _ in 0..10 {
            let state_clone = state.clone();

            let handle = tokio::spawn(async move {
                for i in 0..10 {
                    state_clone.log("INFO", &format!("Concurrent log {}", i)).unwrap();
                }
            });
            
            handles.push(handle);
        }
        
        for handle in handles {
            handle.await.unwrap();
        }
    }

    #[tokio::test]
    async fn test_concurrent_fake_ip_operations() {
        let state = Arc::new(AppState::new());

        let mut handles = Vec::new();

        for i in 0..10 {
            let domain = format!("domain{}.example.com", i);
            let fake_ip = format!("198.18.0.{}", i);

            let state_clone = state.clone();

            let handle = tokio::spawn(async move {
                state_clone.add_fake_ip_entry(&domain, &fake_ip, None);
                
                // Verify the entry was added
                assert!(state_clone.fake_ip_cache.contains_key(&domain));
            });
            
            handles.push(handle);
        }
        
        for handle in handles {
            handle.await.unwrap();
        }
    }

    #[tokio::test]
    async fn test_domain_to_fake_ip_mapping() {
        let state = AppState::new();
        
        state.add_domain_to_fake_ip_mapping("example.com", "198.18.0.5");
        state.add_fake_ip_to_domain_mapping("198.18.0.5", "example.com");
        
        assert_eq!(state.get_fake_ip("example.com"), Some("198.18.0.5".to_string()));
    }

    #[test]
    fn test_clear_logs() {
        let state = AppState::new();
        
        for i in 0..10 {
            state.log("INFO", &format!("Log message {}", i)).unwrap();
        }
        
        assert_eq!(state.logs.lock().unwrap().len(), 10);
        
        state.clear_logs().unwrap();
        
        assert_eq!(state.logs.lock().unwrap().len(), 0);
    }

    #[test]
    fn test_clear_cache() {
        let state = AppState::new();
        
        // Добавляем записи в кэш
        for i in 0..5 {
            let domain = format!("domain{}.com", i);
            let fake_ip = format!("198.18.0.{}", i + 1);
            
            state.add_domain_to_fake_ip_mapping(&domain, &fake_ip);
            state.add_fake_ip_to_domain_mapping(&fake_ip, &domain);
        }
        
        assert_eq!(state.domain_to_fake_ip.len(), 5);
        
        // Очищаем кэш
        state.clear_cache().unwrap();
        
        assert_eq!(state.domain_to_fake_ip.len(), 0);
    }

    #[test]
    fn test_has_cached_domain() {
        let state = AppState::new();
        
        assert!(!state.has_cached_domain("example.com"));
        
        state.add_domain_to_fake_ip_mapping("example.com", "198.18.0.5");
        
        assert!(state.has_cached_domain("example.com"));
    }

    #[test]
    fn test_vpn_status_partial_eq() {
        let status1 = VpnStatus::Connected;
        let status2 = VpnStatus::Connected;
        let status3 = VpnStatus::Disconnected;
        
        assert_eq!(status1, status2);
        assert_ne!(status1, status3);
    }

    #[test]
    fn test_status_partial_eq_variants() {
        assert_eq!(VpnStatus::Connected, VpnStatus::Connected);
        assert_eq!(VpnStatus::Disconnected, VpnStatus::Disconnected);
        assert_eq!(VpnStatus::Connecting, VpnStatus::Connecting);
        assert_eq!(VpnStatus::Disconnecting, VpnStatus::Disconnecting);
        
        assert_ne!(VpnStatus::Connected, VpnStatus::Disconnected);
        assert_ne!(VpnStatus::Connected, VpnStatus::Connecting);
        assert_ne!(VpnStatus::Connected, VpnStatus::Disconnecting);
    }

    #[test]
    fn test_get_profile_id() {
        let state = AppState::new();
        
        // По умолчанию profile_id должен быть None
        assert_eq!(state.get_profile_id(), None);
        
        state.set_profile_id(Some("profile1".to_string()));
        assert_eq!(state.get_profile_id(), Some("profile1".to_string()));
        
        state.set_profile_id(None);
        assert_eq!(state.get_profile_id(), None);
    }
}