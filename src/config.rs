use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
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

#[derive(Debug, Clone, Serialize, Deserialize)]
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubscriptionConfig {
    pub url: String,
    pub refresh_interval_seconds: u64,
    pub max_connections: usize,
}

impl Default for SubscriptionConfig {
    fn default() -> Self {
        Self {
            url: "https://example.com/subscription".to_string(),
            refresh_interval_seconds: 300,
            max_connections: 10,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VpnConfig {
    pub profiles: Vec<ProxyProfile>,
    pub subscription_config: SubscriptionConfig,
    pub dns_settings: DnsSettings,
    pub tun_settings: TunSettings,
}

impl Default for VpnConfig {
    fn default() -> Self {
        Self {
            profiles: Vec::new(),
            subscription_config: SubscriptionConfig::default(),
            dns_settings: DnsSettings::default(),
            tun_settings: TunSettings::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsSettings {
    pub fake_ip_pool_start: String,
    pub fake_ip_pool_end: String,
    pub doh_server: String,
    pub dns_port: u16,
}

impl Default for DnsSettings {
    fn default() -> Self {
        Self {
            fake_ip_pool_start: "198.18.0.0".to_string(),
            fake_ip_pool_end: "198.18.255.255".to_string(),
            doh_server: "https://1.1.1.1/dns-query".to_string(),
            dns_port: 53,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunSettings {
    pub interface_name: String,
    pub mtu: u32,
    pub route_metric: u32,
}

impl Default for TunSettings {
    fn default() -> Self {
        Self {
            interface_name: "vpn-tun".to_string(),
            mtu: 9000,
            route_metric: 10,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vpn_config_default() {
        let config = VpnConfig::default();
        assert_eq!(config.subscription_config.refresh_interval_seconds, 300);
        assert_eq!(config.dns_settings.doh_server, "https://1.1.1.1/dns-query");
    }

    #[test]
    fn test_dns_settings_default() {
        let dns = DnsSettings::default();
        assert_eq!(dns.fake_ip_pool_start, "198.18.0.0");
        assert_eq!(dns.doh_server, "https://1.1.1.1/dns-query");
    }

    #[test]
    fn test_tun_settings_default() {
        let tun = TunSettings::default();
        assert_eq!(tun.mtu, 9000);
        assert_eq!(tun.route_metric, 10);
    }

    #[tokio::test]
    async fn test_profile_serialization() {
        let profile = ProxyProfile {
            id: "uuid-123".to_string(),
            name: "Test Server".to_string(),
            url: "vless://user@server.com".to_string(),
            protocol: ProtocolType::Vless,
            server: "server.com".to_string(),
            port: 443,
            username: Some("user".to_string()),
            password: None,
        };

        let json = serde_json::to_string(&profile).unwrap();
        assert!(json.contains("vless"));
    }
}
