use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use dashmap::{DashMap, DashSet};
use anyhow::Result;
use serde::Deserialize;
use tokio::net::UdpSocket;

use crate::state::AppState;

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

/// Перехватчик DNS-запросов на базе UDP.
///
/// На A-запросы отвечает FakeIP из пула 198.18.0.0/16 и пишет маппинг в `AppState`.
/// На все прочие типы (AAAA и т.д.) возвращает NXDOMAIN, чтобы клиенты
/// использовали только IPv4 FakeIP-адреса.
pub struct DnsProxy {
    bind_addr: SocketAddr,
    allocator: Arc<FakeIpManager>,
}

impl DnsProxy {
    pub fn new(bind_addr: SocketAddr) -> Self {
        Self {
            bind_addr,
            allocator: Arc::new(FakeIpManager::new()),
        }
    }

    /// Запускает цикл приёма DNS-запросов. Завершается только при фатальной ошибке сокета.
    ///
    /// Если передан `ready_tx`, отправляет в него фактический адрес после привязки —
    /// полезно в тестах при `bind` на порт 0.
    pub async fn run(
        self,
        state: Arc<AppState>,
        ready_tx: Option<tokio::sync::oneshot::Sender<SocketAddr>>,
    ) -> Result<()> {
        let socket = Arc::new(
            UdpSocket::bind(self.bind_addr)
                .await
                .map_err(|e| anyhow::anyhow!("DNS proxy: не удалось привязать {} — {}", self.bind_addr, e))?,
        );

        let bound_addr = socket.local_addr()?;
        if let Some(tx) = ready_tx {
            let _ = tx.send(bound_addr);
        }
        state.log("INFO", &format!("DNS proxy слушает {}", bound_addr)).ok();

        loop {
            let mut buf = [0u8; 512];
            let (len, src) = match socket.recv_from(&mut buf).await {
                Ok(v) => v,
                Err(e) => {
                    state.log("ERROR", &format!("DNS recv_from: {}", e)).ok();
                    continue;
                }
            };

            let query = buf[..len].to_vec();
            let socket_clone = socket.clone();
            let state_clone = state.clone();
            let allocator_clone = self.allocator.clone();

            tokio::spawn(async move {
                if let Some(resp) = handle_dns_query(&query, &state_clone, &allocator_clone) {
                    let _ = socket_clone.send_to(&resp, src).await;
                }
            });
        }
    }
}

/// Обрабатывает один DNS-запрос: A → FakeIP, прочие → NXDOMAIN.
fn handle_dns_query(query: &[u8], state: &AppState, allocator: &FakeIpManager) -> Option<Vec<u8>> {
    let (tx_id, domain, qtype) = parse_dns_question(query)?;

    if qtype != 1 {
        return Some(build_nxdomain_response(query, tx_id));
    }

    let fake_ip = if let Some(existing) = state.domain_to_fake_ip.get(&domain) {
        existing.clone()
    } else {
        let ip = allocator.resolve_to_fake_ip(&domain).ok()?;
        state.domain_to_fake_ip.insert(domain.clone(), ip.clone());
        state.fake_ip_to_domain.insert(ip.clone(), domain.clone());
        state.log("INFO", &format!("[FAKEIP] {} -> {}", domain, ip)).ok();
        ip
    };

    build_a_response(query, tx_id, &fake_ip)
}

/// Разбирает заголовок и секцию вопроса DNS-пакета.
/// Возвращает `(tx_id, domain, qtype)` или `None` при любом нарушении формата.
fn parse_dns_question(buf: &[u8]) -> Option<(u16, String, u16)> {
    if buf.len() < 12 {
        return None;
    }
    let tx_id = u16::from_be_bytes([buf[0], buf[1]]);
    if u16::from_be_bytes([buf[4], buf[5]]) == 0 {
        return None; // QDCOUNT = 0
    }

    let mut offset = 12;
    let mut labels: Vec<String> = Vec::new();

    loop {
        if offset >= buf.len() {
            return None;
        }
        let label_len = buf[offset] as usize;
        if label_len == 0 {
            offset += 1;
            break;
        }
        // Compression pointers (0xC0..) не встречаются в клиентских запросах
        if label_len > 63 || offset + 1 + label_len > buf.len() {
            return None;
        }
        labels.push(
            String::from_utf8_lossy(&buf[offset + 1..offset + 1 + label_len]).to_lowercase(),
        );
        offset += 1 + label_len;
    }

    if labels.is_empty() || offset + 4 > buf.len() {
        return None;
    }
    let qtype = u16::from_be_bytes([buf[offset], buf[offset + 1]]);
    Some((tx_id, labels.join("."), qtype))
}

/// Строит DNS A-ответ с FakeIP.
fn build_a_response(query: &[u8], tx_id: u16, fake_ip: &str) -> Option<Vec<u8>> {
    let ip: Ipv4Addr = fake_ip.parse().ok()?;
    let question = &query[12..];

    let mut resp = Vec::with_capacity(12 + question.len() + 16);
    resp.extend_from_slice(&tx_id.to_be_bytes());
    resp.extend_from_slice(&[0x81, 0x80]); // QR=1, RD=1, RA=1, RCODE=0
    resp.extend_from_slice(&[0x00, 0x01]); // QDCOUNT=1
    resp.extend_from_slice(&[0x00, 0x01]); // ANCOUNT=1
    resp.extend_from_slice(&[0x00, 0x00]); // NSCOUNT=0
    resp.extend_from_slice(&[0x00, 0x00]); // ARCOUNT=0
    resp.extend_from_slice(question);
    resp.extend_from_slice(&[0xC0, 0x0C]); // NAME: compressed ptr к offset 12
    resp.extend_from_slice(&[0x00, 0x01]); // TYPE: A
    resp.extend_from_slice(&[0x00, 0x01]); // CLASS: IN
    resp.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]); // TTL: 1 сек
    resp.extend_from_slice(&[0x00, 0x04]); // RDLENGTH: 4 байта
    resp.extend_from_slice(&ip.octets());

    Some(resp)
}

/// Строит DNS NXDOMAIN-ответ (RCODE=3, записей нет).
fn build_nxdomain_response(query: &[u8], tx_id: u16) -> Vec<u8> {
    let question = &query[12..];
    let mut resp = Vec::with_capacity(12 + question.len());
    resp.extend_from_slice(&tx_id.to_be_bytes());
    resp.extend_from_slice(&[0x81, 0x83]); // QR=1, RD=1, RA=1, RCODE=3
    resp.extend_from_slice(&[0x00, 0x01]); // QDCOUNT=1
    resp.extend_from_slice(&[0x00, 0x00]); // ANCOUNT=0
    resp.extend_from_slice(&[0x00, 0x00]); // NSCOUNT=0
    resp.extend_from_slice(&[0x00, 0x00]); // ARCOUNT=0
    resp.extend_from_slice(question);
    resp
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

    // ── DnsProxy helpers ─────────────────────────────────────────────────────

    /// Собирает минимальный DNS-запрос для `domain` с заданным `qtype`.
    fn build_query(tx_id: u16, domain: &str, qtype: u16) -> Vec<u8> {
        let mut q = Vec::new();
        q.extend_from_slice(&tx_id.to_be_bytes());
        q.extend_from_slice(&[0x01, 0x00]); // flags: RD=1
        q.extend_from_slice(&[0x00, 0x01]); // QDCOUNT=1
        q.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]); // AN/NS/AR=0
        for label in domain.split('.') {
            q.push(label.len() as u8);
            q.extend_from_slice(label.as_bytes());
        }
        q.push(0x00); // конец QNAME
        q.extend_from_slice(&qtype.to_be_bytes()); // QTYPE
        q.extend_from_slice(&[0x00, 0x01]);         // QCLASS: IN
        q
    }

    #[test]
    fn test_parse_dns_question_a_record() {
        let query = build_query(0xABCD, "example.com", 1);
        let (tx_id, domain, qtype) = parse_dns_question(&query).unwrap();
        assert_eq!(tx_id, 0xABCD);
        assert_eq!(domain, "example.com");
        assert_eq!(qtype, 1);
    }

    #[test]
    fn test_parse_dns_question_subdomain() {
        let query = build_query(0x0001, "sub.example.com", 1);
        let (_, domain, _) = parse_dns_question(&query).unwrap();
        assert_eq!(domain, "sub.example.com");
    }

    #[test]
    fn test_parse_dns_question_aaaa() {
        let query = build_query(0x0002, "example.com", 28);
        let (_, domain, qtype) = parse_dns_question(&query).unwrap();
        assert_eq!(domain, "example.com");
        assert_eq!(qtype, 28);
    }

    #[test]
    fn test_parse_dns_question_too_short() {
        assert!(parse_dns_question(&[0x00, 0x01]).is_none());
        assert!(parse_dns_question(&[]).is_none());
    }

    #[test]
    fn test_parse_dns_question_zero_qdcount() {
        let mut query = build_query(0x0001, "example.com", 1);
        // Перезапишем QDCOUNT = 0
        query[4] = 0x00;
        query[5] = 0x00;
        assert!(parse_dns_question(&query).is_none());
    }

    #[test]
    fn test_build_a_response_structure() {
        let query = build_query(0x1234, "example.com", 1);
        let resp = build_a_response(&query, 0x1234, "198.18.0.5").unwrap();

        // Заголовок
        assert_eq!(u16::from_be_bytes([resp[0], resp[1]]), 0x1234); // tx_id
        assert_eq!(resp[2], 0x81); // QR=1, RD=1
        assert_eq!(resp[3] & 0x0F, 0x00); // RCODE=0
        assert_eq!(u16::from_be_bytes([resp[6], resp[7]]), 1); // ANCOUNT=1

        // Последние 4 байта — IPv4-адрес
        let ip_bytes = &resp[resp.len() - 4..];
        assert_eq!(ip_bytes, &[198, 18, 0, 5]);
    }

    #[test]
    fn test_build_a_response_invalid_ip() {
        let query = build_query(0x0001, "example.com", 1);
        assert!(build_a_response(&query, 0x0001, "not-an-ip").is_none());
    }

    #[test]
    fn test_build_nxdomain_response_rcode() {
        let query = build_query(0xBEEF, "example.com", 28);
        let resp = build_nxdomain_response(&query, 0xBEEF);

        assert_eq!(u16::from_be_bytes([resp[0], resp[1]]), 0xBEEF);
        assert_eq!(resp[3] & 0x0F, 0x03); // RCODE=3 (NXDOMAIN)
        assert_eq!(u16::from_be_bytes([resp[6], resp[7]]), 0); // ANCOUNT=0
    }

    #[test]
    fn test_handle_dns_query_a_allocates_fake_ip() {
        let state = AppState::new();
        let allocator = FakeIpManager::new();
        let query = build_query(0x0001, "github.com", 1);

        let resp = handle_dns_query(&query, &state, &allocator).unwrap();

        // ANCOUNT=1
        assert_eq!(u16::from_be_bytes([resp[6], resp[7]]), 1);
        // IP в диапазоне 198.18.0.0/16
        let ip = &resp[resp.len() - 4..];
        assert_eq!(ip[0], 198);
        assert_eq!(ip[1], 18);
    }

    #[test]
    fn test_handle_dns_query_aaaa_returns_nxdomain() {
        let state = AppState::new();
        let allocator = FakeIpManager::new();
        let query = build_query(0x0002, "github.com", 28);

        let resp = handle_dns_query(&query, &state, &allocator).unwrap();

        assert_eq!(resp[3] & 0x0F, 0x03); // RCODE=3
        assert_eq!(u16::from_be_bytes([resp[6], resp[7]]), 0); // ANCOUNT=0
    }

    #[test]
    fn test_handle_dns_query_same_domain_same_ip() {
        let state = AppState::new();
        let allocator = FakeIpManager::new();
        let query = build_query(0x0001, "example.com", 1);

        let resp1 = handle_dns_query(&query, &state, &allocator).unwrap();
        let resp2 = handle_dns_query(&query, &state, &allocator).unwrap();

        assert_eq!(&resp1[resp1.len() - 4..], &resp2[resp2.len() - 4..]);
    }

    #[test]
    fn test_handle_dns_query_writes_to_appstate() {
        let state = AppState::new();
        let allocator = FakeIpManager::new();
        let query = build_query(0x0001, "example.com", 1);

        handle_dns_query(&query, &state, &allocator).unwrap();

        assert!(state.domain_to_fake_ip.contains_key("example.com"));
        let fake_ip = state.domain_to_fake_ip.get("example.com").unwrap().clone();
        assert_eq!(
            state.fake_ip_to_domain.get(&fake_ip).unwrap().clone(),
            "example.com"
        );
    }

    #[tokio::test]
    async fn test_dns_proxy_full_roundtrip() {
        use std::time::Duration;
        use tokio::time::timeout;

        let state = Arc::new(AppState::new());
        let (tx, rx) = tokio::sync::oneshot::channel();

        let state_proxy = state.clone();
        tokio::spawn(async move {
            DnsProxy::new("127.0.0.1:0".parse().unwrap())
                .run(state_proxy, Some(tx))
                .await
                .ok();
        });

        let bound_addr = timeout(Duration::from_secs(1), rx).await.unwrap().unwrap();

        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let query = build_query(0xCAFE, "proxy-test.example.com", 1);
        client.send_to(&query, bound_addr).await.unwrap();

        let mut buf = [0u8; 512];
        let (len, _) = timeout(Duration::from_secs(1), client.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();

        let resp = &buf[..len];
        assert_eq!(u16::from_be_bytes([resp[0], resp[1]]), 0xCAFE);
        assert_eq!(u16::from_be_bytes([resp[6], resp[7]]), 1); // ANCOUNT=1
        assert_eq!(resp[resp.len() - 4], 198);
        assert_eq!(resp[resp.len() - 3], 18);
        assert!(state.domain_to_fake_ip.contains_key("proxy-test.example.com"));
    }
}
