use std::collections::HashMap;
use std::sync::Arc;
use dashmap::{DashMap, DashSet};
use anyhow::Result;
use serde::Deserialize;

/// Начало пула FakeIP (198.18.0.0)
const POOL_START: u32 = 0xC612_0000;
/// Конец пула FakeIP (198.18.255.255)
const POOL_END: u32 = 0xC612_FFFF;

pub struct FakeIpManager {
    ip_pool_start: u32,
    ip_pool_end: u32,
    used_ips: DashSet<String>,
    domain_to_ip: DashMap<String, String>,
    ip_to_domain: DashMap<String, String>,
}

impl FakeIpManager {
    pub fn new() -> Self {
        Self {
            ip_pool_start: POOL_START,
            ip_pool_end: POOL_END,
            used_ips: DashSet::new(),
            domain_to_ip: DashMap::new(),
            ip_to_domain: DashMap::new(),
        }
    }

    /// Выделяет первый свободный IP из пула. Не привязывает его к домену.
    pub fn allocate_ip(&self) -> Result<String> {
        let mut current = self.ip_pool_start;

        while current <= self.ip_pool_end {
            let ip_str = format_ip(current);

            if self.used_ips.insert(ip_str.clone()) {
                return Ok(ip_str);
            }

            current += 1;
        }

        Err(anyhow::anyhow!("IP pool exhausted"))
    }

    /// Возвращает FakeIP для домена, выделяя новый при первом обращении.
    pub fn resolve_to_fake_ip(&self, domain: &str) -> Result<String> {
        if let Some(ip) = self.domain_to_ip.get(domain) {
            return Ok(ip.clone());
        }

        let fake_ip = self.allocate_ip()?;
        self.domain_to_ip.insert(domain.to_string(), fake_ip.clone());
        self.ip_to_domain.insert(fake_ip.clone(), domain.to_string());

        Ok(fake_ip)
    }

    /// Обратное разрешение: FakeIP -> домен.
    pub fn resolve_from_fake_ip(&self, fake_ip: &str) -> Result<String> {
        self.ip_to_domain
            .get(fake_ip)
            .map(|entry| entry.value().clone())
            .ok_or_else(|| anyhow::anyhow!("Fake IP не найден в кэше"))
    }

    /// Освобождает FakeIP, выделенный для домена.
    pub fn release_ip(&self, domain: &str) -> Result<()> {
        if let Some((_, fake_ip)) = self.domain_to_ip.remove(domain) {
            self.ip_to_domain.remove(&fake_ip);
            self.used_ips.remove(&fake_ip);
            Ok(())
        } else {
            Err(anyhow::anyhow!("Домен не найден в кэше"))
        }
    }

    pub fn get_stats(&self) -> HashMap<String, usize> {
        let mut stats = HashMap::new();
        stats.insert("allocated".to_string(), self.domain_to_ip.len());
        stats
    }
}

fn format_ip(addr: u32) -> String {
    format!(
        "{}.{}.{}.{}",
        (addr >> 24) & 0xFF,
        (addr >> 16) & 0xFF,
        (addr >> 8) & 0xFF,
        addr & 0xFF
    )
}

fn parse_ip(ip_str: &str) -> Result<u32> {
    let parts: Vec<&str> = ip_str.split('.').collect();

    if parts.len() != 4 {
        return Err(anyhow::anyhow!("Некорректный IP адрес"));
    }

    let mut octets = [0u8; 4];
    for (i, part) in parts.iter().enumerate() {
        octets[i] = part
            .parse()
            .map_err(|_| anyhow::anyhow!("Некорректный IP адрес"))?;
    }

    Ok(((octets[0] as u32) << 24)
        | ((octets[1] as u32) << 16)
        | ((octets[2] as u32) << 8)
        | (octets[3] as u32))
}

/// Ответ Cloudflare DoH в JSON-формате (`application/dns-json`).
#[derive(Debug, Deserialize)]
struct DohResponse {
    #[serde(rename = "Answer")]
    answer: Option<Vec<DohAnswer>>,
}

#[derive(Debug, Deserialize)]
struct DohAnswer {
    #[serde(rename = "type")]
    record_type: u16,
    data: String,
}

/// Клиент DNS-over-HTTPS (Cloudflare `1.1.1.1/dns-query`) с локальным кэшем.
///
/// Примечание по маскировке SNI: `reqwest` использует системный TLS-стек и не
/// позволяет подменить SNI на уровне отдельного запроса без кастомного
/// `rustls::ClientConfig`. Полноценная маскировка (domain fronting) — задача
/// сетевого слоя (Этап 3/4), здесь она оставлена как точка расширения.
pub struct DoHClient {
    http: reqwest::Client,
    endpoint: String,
    cache: DashMap<String, String>,
}

impl DoHClient {
    pub fn new() -> Self {
        Self {
            http: reqwest::Client::new(),
            endpoint: "https://1.1.1.1/dns-query".to_string(),
            cache: DashMap::new(),
        }
    }

    pub fn has_cache(&self, domain: &str) -> bool {
        self.cache.contains_key(domain)
    }

    pub fn get_cache(&self, domain: &str) -> Option<String> {
        self.cache.get(domain).map(|entry| entry.value().clone())
    }

    pub fn set_cache(&self, domain: &str, ip: String) {
        self.cache.insert(domain.to_string(), ip);
    }

    pub fn clear_cache(&self) {
        self.cache.clear();
    }

    /// Резолвит A-запись домена через DoH, используя кэш при наличии записи.
    pub async fn resolve(&self, domain: &str) -> Result<String> {
        if let Some(ip) = self.get_cache(domain) {
            return Ok(ip);
        }

        let response: DohResponse = self
            .http
            .get(&self.endpoint)
            .header("accept", "application/dns-json")
            .query(&[("name", domain), ("type", "A")])
            .send()
            .await?
            .json()
            .await?;

        let ip = response
            .answer
            .unwrap_or_default()
            .into_iter()
            .find(|record| record.record_type == 1) // 1 = A-запись
            .map(|record| record.data)
            .ok_or_else(|| anyhow::anyhow!("DoH: A-запись для {} не найдена", domain))?;

        self.set_cache(domain, ip.clone());
        Ok(ip)
    }
}

/// Связывает FakeIP-менеджер и DoH-клиент в единый DNS-движок приложения.
pub struct DnsEngine {
    pub fake_ip: Arc<FakeIpManager>,
    pub doh: Arc<DoHClient>,
}

impl DnsEngine {
    pub fn new() -> Self {
        Self {
            fake_ip: Arc::new(FakeIpManager::new()),
            doh: Arc::new(DoHClient::new()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ip_pool_allocation() {
        let manager = FakeIpManager::new();

        let ip1 = manager.allocate_ip().unwrap();
        assert!(ip1.starts_with("198.18."));

        let ip2 = manager.allocate_ip().unwrap();
        assert_ne!(ip1, ip2);
    }

    #[tokio::test]
    async fn test_concurrent_allocation() {
        let manager = Arc::new(FakeIpManager::new());

        let handles: Vec<_> = (0..10)
            .map(|_| {
                let manager = manager.clone();
                tokio::spawn(async move { manager.allocate_ip().unwrap_or_default() })
            })
            .collect();

        let mut ips = Vec::new();
        for handle in handles {
            ips.push(handle.await.unwrap());
        }

        // Все выделенные IP должны быть уникальны - без коллизий между потоками.
        let unique: std::collections::HashSet<_> = ips.iter().collect();
        assert_eq!(unique.len(), ips.len());
    }

    #[test]
    fn test_resolve_to_fake_ip_is_stable() {
        let manager = FakeIpManager::new();

        let ip1 = manager.resolve_to_fake_ip("example.com").unwrap();
        let ip2 = manager.resolve_to_fake_ip("example.com").unwrap();

        assert_eq!(ip1, ip2);
        assert!(ip1.starts_with("198.18."));
    }

    #[test]
    fn test_reverse_resolution() {
        let manager = FakeIpManager::new();

        let fake_ip = manager.resolve_to_fake_ip("example.com").unwrap();

        assert_eq!(manager.resolve_from_fake_ip(&fake_ip).unwrap(), "example.com");
    }

    #[test]
    fn test_ip_pool_exhaustion() {
        let manager = FakeIpManager {
            ip_pool_start: parse_ip("198.18.0.0").unwrap(),
            ip_pool_end: parse_ip("198.18.0.4").unwrap(),
            used_ips: DashSet::new(),
            domain_to_ip: DashMap::new(),
            ip_to_domain: DashMap::new(),
        };

        // Пул из 5 адресов - выделяем все.
        for _ in 0..5 {
            assert!(manager.allocate_ip().is_ok());
        }

        // Следующий вызов должен вернуть ошибку.
        assert!(manager.allocate_ip().is_err());
    }

    #[test]
    fn test_domain_release() {
        let manager = FakeIpManager::new();

        let fake_ip = manager.resolve_to_fake_ip("example.com").unwrap();

        assert!(manager.release_ip("example.com").is_ok());
        assert!(manager.resolve_from_fake_ip(&fake_ip).is_err());

        // После освобождения домен снова резолвится (возможно, в тот же IP).
        assert!(manager.release_ip("example.com").is_err());
    }

    #[test]
    fn test_doh_cache_operations() {
        let client = DoHClient::new();

        assert!(!client.has_cache("example.com"));

        client.set_cache("example.com", "93.184.216.34".to_string());

        assert!(client.has_cache("example.com"));
        assert_eq!(client.get_cache("example.com"), Some("93.184.216.34".to_string()));

        client.clear_cache();
        assert!(!client.has_cache("example.com"));
    }

    #[tokio::test]
    async fn test_doh_resolve_uses_cache() {
        let client = DoHClient::new();
        client.set_cache("cached.example.com", "198.18.0.42".to_string());

        let ip = client.resolve("cached.example.com").await.unwrap();
        assert_eq!(ip, "198.18.0.42");
    }

    #[tokio::test]
    #[ignore = "требует доступ в интернет к 1.1.1.1"]
    async fn test_doh_resolve_real_domain() {
        let client = DoHClient::new();
        let ip = client.resolve("cloudflare.com").await.unwrap();
        assert!(!ip.is_empty());
    }

    #[test]
    fn test_dns_engine_construction() {
        let engine = DnsEngine::new();
        assert!(engine.fake_ip.allocate_ip().is_ok());
        assert!(!engine.doh.has_cache("example.com"));
    }
}
