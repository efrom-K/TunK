use std::collections::HashMap;
use dashmap::DashMap;
use uuid::Uuid;
use anyhow::{Result, Context};
use chrono::{DateTime, Utc};

pub struct FakeIpManager {
    ip_pool_start: u32,
    ip_pool_end: u32,
    allocated_ips: DashMap<String, String>, // domain -> fake_ip
    reverse_map: DashMap<String, String>, // fake_ip -> domain
}

impl FakeIpManager {
    pub fn new() -> Self {
        let pool_start = parse_ip("198.18.0.0").unwrap();
        let pool_end = parse_ip("198.18.255.255").unwrap();
        
        Self {
            ip_pool_start: pool_start,
            ip_pool_end: pool_end,
            allocated_ips: DashMap::new(),
            reverse_map: DashMap::new(),
        }
    }

    pub fn allocate_ip(&self) -> Result<String> {
        let mut current = self.ip_pool_start;
        
        while current <= self.ip_pool_end {
            let ip_str = format!("{}.{}.{}.{}", 
                (current >> 24) & 0xFF,
                (current >> 16) & 0xFF,
                (current >> 8) & 0xFF,
                current & 0xFF);
            
            if !self.allocated_ips.contains_key(&ip_str) {
                self.allocated_ips.insert(ip_str.clone(), ip_str.clone());
                self.reverse_map.insert(ip_str.clone(), ip_str.clone());
                
                return Ok(format!("{}.{}.{}.{}", 
                    (current >> 24) & 0xFF,
                    (current >> 16) & 0xFF,
                    (current >> 8) & 0xFF,
                    current & 0xFF));
            }
            
            current += 1;
        }
        
        Err(anyhow::anyhow!("IP pool exhausted"))
    }

    pub fn get_fake_ip_for_domain(&self, domain: &str) -> Result<String> {
        let ip = self.allocate_ip()?;
        Ok(ip)
    }

    pub fn resolve_to_fake_ip(&self, domain: &str) -> Result<String> {
        if let Some(fake_ip) = self.allocated_ips.get(domain).map(|v| v.value().clone()) {
            return Ok(fake_ip);
        }
        
        // Если домен не в кэше, создаем новый IP
        let fake_ip = self.allocate_ip()?;
        self.allocated_ips.insert(domain.to_string(), fake_ip.clone());
        self.reverse_map.insert(fake_ip.clone(), domain.to_string());
        
        Ok(fake_ip)
    }

    pub fn resolve_from_fake_ip(&self, fake_ip: &str) -> Result<String> {
        if let Some(domain) = self.reverse_map.get(fake_ip).map(|v| v.value().clone()) {
            return Ok(domain);
        }
        
        Err(anyhow::anyhow!("Fake IP не найден в кэше"))
    }

    pub fn get_domain_for_fake_ip(&self, fake_ip: &str) -> Result<String> {
        if let Some(domain) = self.reverse_map.get(fake_ip).map(|v| v.value().clone()) {
            return Ok(domain);
        }
        
        Err(anyhow::anyhow!("Fake IP не найден в кэше"))
    }

    pub fn release_ip(&self, domain: &str) -> Result<()> {
        if let Some(entry) = self.allocated_ips.remove(domain) {
            let ip = entry.value().clone();
            self.reverse_map.remove(&ip);
            Ok(())
        } else {
            Err(anyhow::anyhow!("Домен не найден в кэше"))
        }
    }

    pub fn get_stats(&self) -> HashMap<String, usize> {
        let mut stats = HashMap::new();
        
        for entry in self.allocated_ips.iter() {
            *stats.entry("allocated".to_string()).or_insert(0) += 1;
        }
        
        stats
    }
}

fn parse_ip(ip_str: &str) -> Result<u32> {
    let parts: Vec<&str> = ip_str.split('.').collect();
    
    if parts.len() != 4 {
        return Err(anyhow::anyhow!("Некорректный IP адрес"));
    }

    let octets: Result<Vec<u8>, _> = parts.iter().map(|p| p.parse()).collect();
    
    match octets {
        Ok(octets) => {
            ((octets[0] as u32) << 24) |
            ((octets[1] as u32) << 16) |
            ((octets[2] as u32) << 8) |
            (octets[3] as u32)
        }
        Err(_) => Err(anyhow::anyhow!("Ошибка парсинга IP")),
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
        let manager = FakeIpManager::new();
        
        let handles: Vec<_> = (0..10)
            .map(|_| tokio::spawn(async move {
                manager.allocate_ip().unwrap_or_default()
            }))
            .collect();
        
        for handle in handles {
            let _ip = handle.await.unwrap();
        }
    }

    #[test]
    fn test_reverse_resolution() {
        let manager = FakeIpManager::new();
        
        let fake_ip = manager.allocate_ip().unwrap();
        let domain = "example.com";
        
        // Создаем маппинг вручную для теста
        manager.allocated_ips.insert(domain.to_string(), fake_ip.clone());
        manager.reverse_map.insert(fake_ip.clone(), domain.to_string());
        
        assert_eq!(manager.resolve_from_fake_ip(&fake_ip).unwrap(), domain);
    }

    #[test]
    fn test_ip_pool_exhaustion() {
        let pool_start = parse_ip("198.18.0.0").unwrap();
        let pool_end = parse_ip("198.18.0.5").unwrap();
        
        // Создаем менеджер с маленьким пулом для теста
        let mut manager = FakeIpManager {
            ip_pool_start: pool_start,
            ip_pool_end: pool_end,
            allocated_ips: DashMap::new(),
            reverse_map: DashMap::new(),
        };
        
        // Выделяем все IP из маленького пула
        for _ in 0..5 {
            let _ = manager.allocate_ip();
        }
        
        // Следующий вызов должен вернуть ошибку
        assert!(manager.allocate_ip().is_err());
    }

    #[test]
    fn test_domain_release() {
        let manager = FakeIpManager::new();
        
        let fake_ip = "198.18.0.5";
        let domain = "example.com";
        
        manager.allocated_ips.insert(domain.to_string(), fake_ip.to_string());
        manager.reverse_map.insert(fake_ip.to_string(), domain.to_string());
        
        assert!(manager.release_ip("example.com").is_ok());
        assert!(!manager.allocated_ips.contains_key("example.com"));
    }
}
