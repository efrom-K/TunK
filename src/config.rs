use base64::{engine::general_purpose, Engine as _};
use percent_encoding::percent_decode_str;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::PathBuf;
use uuid::Uuid;

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
    /// Публичный ключ REALITY (`pbk`, base64url X25519), если используется `security=reality`.
    #[serde(default)]
    pub reality_public_key: Option<String>,
    /// Short ID REALITY (`sid`, hex), если используется `security=reality`.
    #[serde(default)]
    pub reality_short_id: Option<String>,
    /// SNI камуфляжа для REALITY/TLS (`sni`).
    #[serde(default)]
    pub sni: Option<String>,
    /// Режим потока, например `xtls-rprx-vision` (`flow`).
    #[serde(default)]
    pub flow: Option<String>,
    /// TLS fingerprint для имитации клиента (`fp`), например `firefox`.
    #[serde(default)]
    pub fingerprint: Option<String>,
    /// Использовать обычный TLS (security=tls без REALITY).
    #[serde(default)]
    pub tls: bool,
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

/// Разбирает строку подписки одного из поддерживаемых форматов
/// (`vless://`, `ss://`, `trojan://`) в `ProxyProfile`.
pub fn parse_subscription_url(url: &str) -> Result<ProxyProfile, String> {
    if let Some(rest) = url.strip_prefix("vless://") {
        parse_vless_url(url, rest)
    } else if let Some(rest) = url.strip_prefix("ss://") {
        parse_shadowsocks_url(url, rest)
    } else if let Some(rest) = url.strip_prefix("trojan://") {
        parse_trojan_url(url, rest)
    } else {
        Err(format!("Неподдерживаемая схема подписки: {}", url))
    }
}

/// Разбирает `vless://uuid@host:port?params#name`.
fn parse_vless_url(original_url: &str, rest: &str) -> Result<ProxyProfile, String> {
    let body = strip_query_and_fragment(rest);

    let (uuid, host_port) = body
        .split_once('@')
        .ok_or_else(|| format!("Некорректный VLESS URL: отсутствует UUID: {}", original_url))?;

    if uuid.is_empty() {
        return Err(format!("Некорректный VLESS URL: пустой UUID: {}", original_url));
    }

    let (server, port) = split_host_port(host_port)?;
    let name = extract_fragment_name(rest, &server);
    let params = parse_query_params(rest);

    Ok(ProxyProfile {
        id: Uuid::new_v4().to_string(),
        name,
        url: original_url.to_string(),
        protocol: ProtocolType::Vless,
        server,
        port,
        username: Some(uuid.to_string()),
        password: None,
        reality_public_key: params.get("pbk").cloned(),
        reality_short_id: params.get("sid").cloned(),
        sni: params.get("sni").cloned(),
        flow: params.get("flow").cloned(),
        fingerprint: params.get("fp").cloned(),
        tls: params.get("security").map(|s| s == "tls").unwrap_or(false),
    })
}

/// Разбирает `trojan://password@host:port?params#name`.
fn parse_trojan_url(original_url: &str, rest: &str) -> Result<ProxyProfile, String> {
    let body = strip_query_and_fragment(rest);

    let (password, host_port) = body
        .split_once('@')
        .ok_or_else(|| format!("Некорректный Trojan URL: отсутствует пароль: {}", original_url))?;

    if password.is_empty() {
        return Err(format!("Некорректный Trojan URL: пустой пароль: {}", original_url));
    }

    let (server, port) = split_host_port(host_port)?;
    let name = extract_fragment_name(rest, &server);

    Ok(ProxyProfile {
        id: Uuid::new_v4().to_string(),
        name,
        url: original_url.to_string(),
        protocol: ProtocolType::Trojan,
        server,
        port,
        username: None,
        password: Some(password.to_string()),
        reality_public_key: None,
        reality_short_id: None,
        sni: None,
        flow: None,
        fingerprint: None,
        tls: false,
    })
}

/// Разбирает `ss://base64(method:password)@host:port#name`.
fn parse_shadowsocks_url(original_url: &str, rest: &str) -> Result<ProxyProfile, String> {
    let body = strip_query_and_fragment(rest);

    let (userinfo, host_port) = body
        .split_once('@')
        .ok_or_else(|| format!("Некорректный Shadowsocks URL: отсутствуют учетные данные: {}", original_url))?;

    let decoded = decode_base64_userinfo(userinfo)?;
    let (method, password) = decoded
        .split_once(':')
        .ok_or_else(|| format!("Некорректные учетные данные Shadowsocks: {}", decoded))?;

    let (server, port) = split_host_port(host_port)?;
    let name = extract_fragment_name(rest, &server);

    Ok(ProxyProfile {
        id: Uuid::new_v4().to_string(),
        name,
        url: original_url.to_string(),
        protocol: ProtocolType::Shadowsocks,
        server,
        port,
        username: Some(method.to_string()),
        password: Some(password.to_string()),
        reality_public_key: None,
        reality_short_id: None,
        sni: None,
        flow: None,
        fingerprint: None,
        tls: false,
    })
}

/// Отрезает query-строку (`?...`) и fragment (`#...`) от части URL после userinfo/хоста.
fn strip_query_and_fragment(value: &str) -> &str {
    let without_fragment = value.split('#').next().unwrap_or(value);
    without_fragment.split('?').next().unwrap_or(without_fragment)
}

/// Разбирает query-строку (`?key=value&...`) на карту параметров с percent-декодированием значений.
/// Fragment (`#...`) отрезается перед разбором.
fn parse_query_params(value: &str) -> std::collections::HashMap<String, String> {
    let without_fragment = value.split('#').next().unwrap_or(value);

    let query = match without_fragment.find('?') {
        Some(idx) => &without_fragment[idx + 1..],
        None => return std::collections::HashMap::new(),
    };

    query
        .split('&')
        .filter_map(|pair| {
            let (key, val) = pair.split_once('=')?;
            let decoded_value = percent_decode_str(val)
                .decode_utf8()
                .map(|v| v.to_string())
                .unwrap_or_else(|_| val.to_string());
            Some((key.to_string(), decoded_value))
        })
        .collect()
}

/// Разбирает `host:port` на хост и порт.
fn split_host_port(host_port: &str) -> Result<(String, u16), String> {
    let (host, port_str) = host_port
        .rsplit_once(':')
        .ok_or_else(|| format!("Некорректный адрес сервера: {}", host_port))?;

    let port = port_str
        .parse::<u16>()
        .map_err(|_| format!("Некорректный порт: {}", port_str))?;

    if host.is_empty() {
        return Err(format!("Некорректный адрес сервера: {}", host_port));
    }

    Ok((host.to_string(), port))
}

/// Декодирует имя профиля из fragment-части URL (`#name`), пробуя несколько форматов.
fn extract_fragment_name(value: &str, default: &str) -> String {
    match value.find('#') {
        Some(idx) => percent_decode_str(&value[idx + 1..])
            .decode_utf8()
            .map(|name| name.to_string())
            .unwrap_or_else(|_| default.to_string()),
        None => default.to_string(),
    }
}

/// Разбирает подписку в формате sing-box JSON (массив конфигов или один конфиг).
/// Извлекает VLESS outbounds. Возвращает пустой Vec если JSON валиден, но VLESS не найден.
/// Возвращает Err только если строка не является валидным JSON.
pub fn parse_singbox_json(json: &str) -> Result<Vec<ProxyProfile>, String> {
    let root: serde_json::Value =
        serde_json::from_str(json).map_err(|e| format!("Невалидный JSON: {}", e))?;

    let configs: Vec<&serde_json::Value> = match &root {
        serde_json::Value::Array(arr) => arr.iter().collect(),
        obj @ serde_json::Value::Object(_) => vec![obj],
        _ => return Ok(Vec::new()),
    };

    let mut profiles = Vec::new();
    let mut seen: HashSet<(String, u16)> = HashSet::new();

    for config in configs {
        let outbounds = match config.get("outbounds").and_then(|v| v.as_array()) {
            Some(arr) => arr,
            None => continue,
        };

        for outbound in outbounds {
            let protocol = match outbound.get("protocol").and_then(|v| v.as_str()) {
                Some(p) => p,
                None => continue,
            };

            // Skip non-VLESS and utility outbound types
            match protocol {
                "vless" => {}
                "freedom" | "blackhole" | "socks" | "http" | "dns" => continue,
                _ => continue,
            }

            // Parse VLESS settings
            let vnext = outbound
                .pointer("/settings/vnext")
                .and_then(|v| v.as_array())
                .and_then(|arr| arr.first());

            let vnext = match vnext {
                Some(v) => v,
                None => continue,
            };

            let server = match vnext.get("address").and_then(|v| v.as_str()) {
                Some(s) if !s.is_empty() => s.to_string(),
                _ => continue,
            };

            let port = match vnext.get("port").and_then(|v| v.as_u64()) {
                Some(p) if p <= 65535 => p as u16,
                _ => continue,
            };

            // Skip duplicates by (server, port)
            if !seen.insert((server.clone(), port)) {
                continue;
            }

            let uuid = vnext
                .pointer("/users/0/id")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();

            let flow = vnext
                .pointer("/users/0/flow")
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string());

            let tag = outbound
                .get("tag")
                .and_then(|v| v.as_str())
                .unwrap_or(&server)
                .to_string();

            // Parse stream settings
            let security = outbound
                .pointer("/streamSettings/security")
                .and_then(|v| v.as_str())
                .unwrap_or("none");

            let (reality_public_key, reality_short_id, sni, fingerprint, tls) = match security {
                "reality" => {
                    let rs = outbound.pointer("/streamSettings/realitySettings");
                    let pbk = rs
                        .and_then(|r| r.get("publicKey"))
                        .and_then(|v| v.as_str())
                        .filter(|s| !s.is_empty())
                        .map(|s| s.to_string());
                    let sid = rs
                        .and_then(|r| r.get("shortId"))
                        .and_then(|v| v.as_str())
                        .filter(|s| !s.is_empty())
                        .map(|s| s.to_string());
                    let sni_val = rs
                        .and_then(|r| r.get("serverName"))
                        .and_then(|v| v.as_str())
                        .filter(|s| !s.is_empty())
                        .map(|s| s.to_string());
                    let fp = rs
                        .and_then(|r| r.get("fingerprint"))
                        .and_then(|v| v.as_str())
                        .filter(|s| !s.is_empty())
                        .map(|s| s.to_string());
                    (pbk, sid, sni_val, fp, false)
                }
                "tls" => {
                    let ts = outbound.pointer("/streamSettings/tlsSettings");
                    let sni_val = ts
                        .and_then(|t| t.get("serverName"))
                        .and_then(|v| v.as_str())
                        .filter(|s| !s.is_empty())
                        .map(|s| s.to_string());
                    (None, None, sni_val, None, true)
                }
                _ => (None, None, None, None, false),
            };

            profiles.push(ProxyProfile {
                id: Uuid::new_v4().to_string(),
                name: tag,
                url: String::new(),
                protocol: ProtocolType::Vless,
                server,
                port,
                username: Some(uuid),
                password: None,
                reality_public_key,
                reality_short_id,
                sni,
                flow,
                fingerprint,
                tls,
            });
        }
    }

    Ok(profiles)
}

/// Возвращает путь к файлу персистентных профилей (`%APPDATA%\TunKVPN\profiles.json`).
fn profiles_path() -> PathBuf {
    let base = std::env::var("APPDATA").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(base).join("TunKVPN").join("profiles.json")
}

/// Сохраняет список профилей в JSON-файл.
pub fn save_profiles(profiles: &[ProxyProfile]) -> anyhow::Result<()> {
    let path = profiles_path();
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let json = serde_json::to_string_pretty(profiles)?;
    std::fs::write(&path, json)?;
    Ok(())
}

/// Загружает профили из JSON-файла. Возвращает пустой Vec если файл отсутствует.
pub fn load_profiles() -> anyhow::Result<Vec<ProxyProfile>> {
    let path = profiles_path();
    if !path.exists() {
        return Ok(Vec::new());
    }
    let content = std::fs::read_to_string(&path)?;
    let profiles: Vec<ProxyProfile> = serde_json::from_str(&content)?;
    Ok(profiles)
}

/// Декодирует userinfo `ss://` подписки (`method:password`), пробуя несколько base64-вариантов.
fn decode_base64_userinfo(data: &str) -> Result<String, String> {
    let engines: [&base64::engine::GeneralPurpose; 4] = [
        &general_purpose::URL_SAFE_NO_PAD,
        &general_purpose::STANDARD_NO_PAD,
        &general_purpose::URL_SAFE,
        &general_purpose::STANDARD,
    ];

    for engine in engines {
        if let Ok(bytes) = engine.decode(data) {
            if let Ok(text) = String::from_utf8(bytes) {
                return Ok(text);
            }
        }
    }

    Err(format!("Не удалось декодировать учетные данные Shadowsocks: {}", data))
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
            reality_public_key: None,
            reality_short_id: None,
            sni: None,
            flow: None,
            fingerprint: None,
            tls: false,
        };

        let json = serde_json::to_string(&profile).unwrap();
        assert!(json.contains("vless"));
    }

    #[test]
    fn test_parse_vless_url() {
        let url = "vless://550e8400-e29b-41d4-a716-446655440000@example.com:443?security=tls#My%20Server";

        let profile = parse_subscription_url(url).unwrap();

        assert!(matches!(profile.protocol, ProtocolType::Vless));
        assert_eq!(profile.server, "example.com");
        assert_eq!(profile.port, 443);
        assert_eq!(profile.username.as_deref(), Some("550e8400-e29b-41d4-a716-446655440000"));
        assert_eq!(profile.password, None);
        assert_eq!(profile.name, "My Server");
        assert_eq!(profile.url, url);
        assert_eq!(profile.reality_public_key, None);
        assert_eq!(profile.reality_short_id, None);
        assert_eq!(profile.sni, None);
        assert_eq!(profile.flow, None);
        assert_eq!(profile.fingerprint, None);
    }

    #[test]
    fn test_parse_vless_url_with_reality_params() {
        let url = "vless://550e8400-e29b-41d4-a716-446655440000@example.com:443?security=reality&encryption=none&pbk=AbCdEf1234567890_-AbCdEf1234567890_-AbCdEf1234&fp=firefox&type=tcp&flow=xtls-rprx-vision&sni=storage.example.net&sid=ab12cd34#%F0%9F%87%BANode";

        let profile = parse_subscription_url(url).unwrap();

        assert!(matches!(profile.protocol, ProtocolType::Vless));
        assert_eq!(profile.server, "example.com");
        assert_eq!(profile.port, 443);
        assert_eq!(
            profile.reality_public_key.as_deref(),
            Some("AbCdEf1234567890_-AbCdEf1234567890_-AbCdEf1234")
        );
        assert_eq!(profile.reality_short_id.as_deref(), Some("ab12cd34"));
        assert_eq!(profile.sni.as_deref(), Some("storage.example.net"));
        assert_eq!(profile.flow.as_deref(), Some("xtls-rprx-vision"));
        assert_eq!(profile.fingerprint.as_deref(), Some("firefox"));
    }

    #[test]
    fn test_parse_trojan_url() {
        let url = "trojan://supersecret@trojan.example.com:8443?sni=example.com#Trojan%20Node";

        let profile = parse_subscription_url(url).unwrap();

        assert!(matches!(profile.protocol, ProtocolType::Trojan));
        assert_eq!(profile.server, "trojan.example.com");
        assert_eq!(profile.port, 8443);
        assert_eq!(profile.username, None);
        assert_eq!(profile.password.as_deref(), Some("supersecret"));
        assert_eq!(profile.name, "Trojan Node");
    }

    #[test]
    fn test_parse_shadowsocks_url() {
        let userinfo = general_purpose::STANDARD.encode("aes-256-gcm:my-password");
        let url = format!("ss://{}@ss.example.com:8388#SS%20Node", userinfo);

        let profile = parse_subscription_url(&url).unwrap();

        assert!(matches!(profile.protocol, ProtocolType::Shadowsocks));
        assert_eq!(profile.server, "ss.example.com");
        assert_eq!(profile.port, 8388);
        assert_eq!(profile.username.as_deref(), Some("aes-256-gcm"));
        assert_eq!(profile.password.as_deref(), Some("my-password"));
        assert_eq!(profile.name, "SS Node");
    }

    #[test]
    fn test_parse_subscription_url_without_fragment_uses_host_as_name() {
        let url = "vless://uuid-value@example.com:443";

        let profile = parse_subscription_url(url).unwrap();

        assert_eq!(profile.name, "example.com");
    }

    #[test]
    fn test_parse_subscription_url_invalid_scheme() {
        let result = parse_subscription_url("http://example.com");

        assert!(result.is_err());
    }

    #[test]
    fn test_parse_subscription_url_missing_userinfo() {
        let result = parse_subscription_url("vless://example.com:443");

        assert!(result.is_err());
    }

    #[test]
    fn test_parse_subscription_url_invalid_port() {
        let result = parse_subscription_url("trojan://password@example.com:notaport");

        assert!(result.is_err());
    }

    // ─── parse_singbox_json tests ─────────────────────────────────────────────

    fn singbox_reality_json() -> &'static str {
        r#"[{
            "outbounds": [{
                "protocol": "vless",
                "tag": "my-reality-node",
                "settings": {
                    "vnext": [{
                        "address": "reality.example.com",
                        "port": 443,
                        "users": [{"id": "550e8400-e29b-41d4-a716-446655440000", "flow": "xtls-rprx-vision"}]
                    }]
                },
                "streamSettings": {
                    "security": "reality",
                    "realitySettings": {
                        "publicKey": "AbCdEf1234567890_-AbCdEf1234567890_-AbCdEf1234",
                        "shortId": "ab12cd34",
                        "serverName": "camouflage.example.com",
                        "fingerprint": "firefox"
                    }
                }
            }]
        }]"#
    }

    #[test]
    fn test_parse_singbox_json_vless_reality() {
        let profiles = parse_singbox_json(singbox_reality_json()).unwrap();
        assert_eq!(profiles.len(), 1);
        let p = &profiles[0];
        assert_eq!(p.name, "my-reality-node");
        assert_eq!(p.server, "reality.example.com");
        assert_eq!(p.port, 443);
        assert_eq!(p.username.as_deref(), Some("550e8400-e29b-41d4-a716-446655440000"));
        assert_eq!(p.flow.as_deref(), Some("xtls-rprx-vision"));
        assert_eq!(
            p.reality_public_key.as_deref(),
            Some("AbCdEf1234567890_-AbCdEf1234567890_-AbCdEf1234")
        );
        assert_eq!(p.reality_short_id.as_deref(), Some("ab12cd34"));
        assert_eq!(p.sni.as_deref(), Some("camouflage.example.com"));
        assert_eq!(p.fingerprint.as_deref(), Some("firefox"));
        assert!(!p.tls);
        assert!(matches!(p.protocol, ProtocolType::Vless));
    }

    #[test]
    fn test_parse_singbox_json_skips_non_vless() {
        let json = r#"[{
            "outbounds": [
                {"protocol": "freedom", "tag": "direct"},
                {"protocol": "blackhole", "tag": "block"},
                {"protocol": "socks", "tag": "socks-out"},
                {"protocol": "http", "tag": "http-out"},
                {"protocol": "dns", "tag": "dns-out"},
                {
                    "protocol": "vless",
                    "tag": "real-vless",
                    "settings": {
                        "vnext": [{"address": "vless.example.com", "port": 443, "users": [{"id": "test-uuid"}]}]
                    },
                    "streamSettings": {"security": "none"}
                }
            ]
        }]"#;
        let profiles = parse_singbox_json(json).unwrap();
        assert_eq!(profiles.len(), 1);
        assert_eq!(profiles[0].name, "real-vless");
    }

    #[test]
    fn test_parse_singbox_json_tls_sets_tls_flag() {
        let json = r#"[{
            "outbounds": [{
                "protocol": "vless",
                "tag": "tls-node",
                "settings": {
                    "vnext": [{"address": "tls.example.com", "port": 8443, "users": [{"id": "tls-uuid"}]}]
                },
                "streamSettings": {
                    "security": "tls",
                    "tlsSettings": {"serverName": "tls.example.com"}
                }
            }]
        }]"#;
        let profiles = parse_singbox_json(json).unwrap();
        assert_eq!(profiles.len(), 1);
        assert!(profiles[0].tls);
        assert_eq!(profiles[0].sni.as_deref(), Some("tls.example.com"));
        assert!(profiles[0].reality_public_key.is_none());
    }

    #[test]
    fn test_parse_singbox_json_invalid_json_returns_err() {
        let result = parse_singbox_json("not valid json {{{");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_singbox_json_no_vless_returns_empty() {
        let json = r#"[{"outbounds": [{"protocol": "freedom", "tag": "direct"}]}]"#;
        let profiles = parse_singbox_json(json).unwrap();
        assert!(profiles.is_empty());
    }

    #[test]
    fn test_parse_singbox_json_deduplicates_by_server_port() {
        let json = r#"[{
            "outbounds": [
                {
                    "protocol": "vless", "tag": "node1",
                    "settings": {"vnext": [{"address": "dup.example.com", "port": 443, "users": [{"id": "u1"}]}]},
                    "streamSettings": {"security": "none"}
                },
                {
                    "protocol": "vless", "tag": "node2",
                    "settings": {"vnext": [{"address": "dup.example.com", "port": 443, "users": [{"id": "u2"}]}]},
                    "streamSettings": {"security": "none"}
                }
            ]
        }]"#;
        let profiles = parse_singbox_json(json).unwrap();
        // second entry with same (server, port) must be deduped
        assert_eq!(profiles.len(), 1);
        assert_eq!(profiles[0].name, "node1");
    }

    #[test]
    fn test_parse_singbox_json_single_object_not_array() {
        let json = r#"{
            "outbounds": [{
                "protocol": "vless",
                "tag": "single-obj",
                "settings": {"vnext": [{"address": "single.example.com", "port": 1234, "users": [{"id": "uid"}]}]},
                "streamSettings": {"security": "none"}
            }]
        }"#;
        let profiles = parse_singbox_json(json).unwrap();
        assert_eq!(profiles.len(), 1);
        assert_eq!(profiles[0].server, "single.example.com");
    }

    #[test]
    fn test_profiles_path_has_json_extension() {
        let path = super::profiles_path();
        assert_eq!(path.extension().and_then(|e| e.to_str()), Some("json"));
    }
}
