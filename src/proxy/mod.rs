use anyhow::{Result, Context};
use regex::Regex;
use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};

pub mod obfuscation;
pub mod sniffer;

#[derive(Debug, Clone)]
pub struct ProxyProfile {
    pub id: String,
    pub name: String,
    pub url: String,
    pub protocol: ProtocolType,
    pub server: String,
    pub port: u16,
    pub username: Option<String>,
    pub password: Option<String>,
}

#[derive(Debug, Clone)]
pub enum ProtocolType {
    Vless,
    Shadowsocks,
    Trojan,
}

impl From<ProtocolType> for String {
    fn from(protocol: ProtocolType) -> Self {
        match protocol {
            ProtocolType::Vless => "vless".to_string(),
            ProtocolType::Shadowsocks => "ss".to_string(),
            ProtocolType::Trojan => "trojan".to_string(),
        }
    }
}

pub fn parse_vless_url(url: &str) -> Result<ProxyProfile, String> {
    let vless_regex = Regex::new(r"^vless://([a-zA-Z0-9_\-]+):?(@)?([^\s/]+)(:\d+)?(/.*)?$").unwrap();
    
    if let Some(caps) = vless_regex.captures(url) {
        let user = caps.get(1).map(|m| m.as_str()).unwrap_or("").to_string();
        let server = caps.get(3).map(|m| m.as_str()).unwrap_or("").to_string();
        
        let port: u16 = if let Some(port_match) = caps.get(4) {
            port_match.as_str().parse()
                .context("Ошибка парсинга порта")?
        } else {
            443 // Default port for VLESS
        };

        Ok(ProxyProfile {
            id: uuid::Uuid::new_v4().to_string(),
            name: format!("VLESS: {}", server),
            url: url.to_string(),
            protocol: ProtocolType::Vless,
            server,
            port,
            username: if caps.get(2).is_some() { Some(user) } else { None },
            password: None,
        })
    } else {
        Err(format!("Некорректный VLESS URL: {}", url))
    }
}

pub fn parse_shadowsocks_url(url: &str) -> Result<ProxyProfile, String> {
    let ss_regex = Regex::new(r"^ss://([A-Za-z0-9+/=]+)(@)?([^\s/]+)(:\d+)?(/.*)?$").unwrap();
    
    if let Some(caps) = ss_regex.captures(url) {
        let encoded_data = caps.get(1).map(|m| m.as_str()).unwrap_or("").to_string();
        let server = caps.get(3).map(|m| m.as_str()).unwrap_or("").to_string();
        
        let port: u16 = if let Some(port_match) = caps.get(4) {
            port_match.as_str().parse()
                .context("Ошибка парсинга порта")?
        } else {
            8388 // Default port for Shadowsocks
        };

        Ok(ProxyProfile {
            id: uuid::Uuid::new_v4().to_string(),
            name: format!("Shadowsocks: {}", server),
            url: url.to_string(),
            protocol: ProtocolType::Shadowsocks,
            server,
            port,
            username: None,
            password: Some(encoded_data),
        })
    } else {
        Err(format!("Некорректный Shadowsocks URL: {}", url))
    }
}

pub fn parse_subscription(url: &str) -> Result<Vec<ProxyProfile>, String> {
    let mut profiles = Vec::new();
    
    if url.starts_with("vless://") {
        profiles.push(parse_vless_url(url)?);
    } else if url.starts_with("ss://") {
        profiles.push(parse_shadowsocks_url(url)?);
    } else {
        return Err(format!("Неподдерживаемый формат подписки: {}", url));
    }
    
    Ok(profiles)
}

pub fn obfuscate_tcp_packet(data: &[u8]) -> Vec<u8> {
    // Базовая обфускация TCP пакета
    let mut result = data.to_vec();
    
    // Добавляем заголовок для инкапсуляции
    result.insert(0, 0x10); // Magic byte for obfuscation
    
    Ok(result)
}

pub fn deobfuscate_tcp_packet(data: &[u8]) -> Result<Vec<u8>, String> {
    if data.is_empty() || data[0] != 0x10 {
        return Err("Некорректный обфусцированный пакет".to_string());
    }
    
    let mut result = Vec::with_capacity(data.len() - 1);
    result.extend_from_slice(&data[1..]);
    
    Ok(result)
}

pub fn obfuscate_udp_packet(data: &[u8]) -> Vec<u8> {
    // Базовая обфускация UDP пакета
    let mut result = data.to_vec();
    
    // Добавляем заголовок для инкапсуляции
    result.insert(0, 0x20); // Magic byte for obfuscation
    
    Ok(result)
}

pub fn deobfuscate_udp_packet(data: &[u8]) -> Result<Vec<u8>, String> {
    if data.is_empty() || data[0] != 0x20 {
        return Err("Некорректный обфусцированный пакет".to_string());
    }
    
    let mut result = Vec::with_capacity(data.len() - 1);
    result.extend_from_slice(&data[1..]);
    
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_vless_url() {
        let url = "vless://user@server.com:443/path";
        let profile = parse_vless_url(url).unwrap();
        
        assert_eq!(profile.protocol, ProtocolType::Vless);
        assert_eq!(profile.server, "server.com");
        assert_eq!(profile.port, 443);
    }

    #[test]
    fn test_parse_shadowsocks_url() {
        let url = "ss://base64data@server.com:8388/path";
        let profile = parse_shadowsocks_url(url).unwrap();
        
        assert_eq!(profile.protocol, ProtocolType::Shadowsocks);
        assert_eq!(profile.server, "server.com");
        assert_eq!(profile.port, 8388);
    }

    #[test]
    fn test_parse_subscription_vless() {
        let url = "vless://user@server.com:443";
        let profiles = parse_subscription(url).unwrap();
        
        assert_eq!(profiles.len(), 1);
        assert_eq!(profiles[0].protocol, ProtocolType::Vless);
    }

    #[test]
    fn test_parse_subscription_ss() {
        let url = "ss://base64data@server.com:8388";
        let profiles = parse_subscription(url).unwrap();
        
        assert_eq!(profiles.len(), 1);
        assert_eq!(profiles[0].protocol, ProtocolType::Shadowsocks);
    }

    #[test]
    fn test_parse_invalid_url() {
        let url = "invalid://url";
        let result = parse_subscription(url);
        
        assert!(result.is_err());
    }

    #[test]
    fn test_tcp_obfuscation() {
        let original_data = b"Hello, World!";
        let obfuscated = obfuscate_tcp_packet(original_data);
        
        assert_eq!(obfuscated[0], 0x10);
        assert_eq!(obfuscated.len(), original_data.len() + 1);
    }

    #[test]
    fn test_tcp_deobfuscation() {
        let original_data = b"Hello, World!";
        let obfuscated = obfuscate_tcp_packet(original_data);
        
        let deobfuscated = deobfuscate_tcp_packet(&obfuscated).unwrap();
        
        assert_eq!(deobfuscated, original_data);
    }

    #[test]
    fn test_udp_obfuscation() {
        let original_data = b"UDP Packet Data";
        let obfuscated = obfuscate_udp_packet(original_data);
        
        assert_eq!(obfuscated[0], 0x20);
        assert_eq!(obfuscated.len(), original_data.len() + 1);
    }

    #[test]
    fn test_udp_deobfuscation() {
        let original_data = b"UDP Packet Data";
        let obfuscated = obfuscate_udp_packet(original_data);
        
        let deobfuscated = deobfuscate_udp_packet(&obfuscated).unwrap();
        
        assert_eq!(deobfuscated, original_data);
    }

    #[test]
    fn test_deobfuscation_invalid_magic() {
        let invalid_data = b"Invalid Packet";
        
        assert!(deobfuscate_tcp_packet(invalid_data).is_err());
        assert!(deobfuscate_udp_packet(invalid_data).is_err());
    }

    #[test]
    fn test_deobfuscation_empty() {
        let empty_data: &[u8] = &[];
        
        assert!(deobfuscate_tcp_packet(empty_data).is_err());
        assert!(deobfuscate_udp_packet(empty_data).is_err());
    }
}
