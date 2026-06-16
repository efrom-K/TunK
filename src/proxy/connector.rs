//! Реальные протокольные хендшейки и AEAD-шифрование для подключения к
//! VLESS/Shadowsocks/Trojan серверам.
//!
//! В отличие от `obfuscation.rs` (который только оборачивает байты в
//! заголовки длины для модульных тестов), этот модуль умеет:
//! - собирать настоящие запросы протоколов (VLESS request header,
//!   Trojan auth header, Shadowsocks AEAD address request);
//! - выполнять Shadowsocks AEAD шифрование/дешифрование с производным
//!   ключом (EVP_BytesToKey + HKDF-SHA1), как описано в спецификации
//!   Shadowsocks AEAD;
//! - открывать TCP-соединение до прокси-сервера и отправлять хендшейк.

use std::net::IpAddr;
use std::time::{Duration, Instant};

use aes_gcm::{Aes128Gcm, Aes256Gcm};
use aead::{Aead, KeyInit};
use anyhow::{anyhow, Result};
use chacha20poly1305::ChaCha20Poly1305;
use hkdf::Hkdf;
use md5::Md5;
use rand::RngCore;
use sha1::Sha1;
use sha2::{Digest, Sha224};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::time::timeout;
use uuid::Uuid;

use crate::config::{ProtocolType, ProxyProfile};
use crate::proxy::reality::build_and_seal_client_hello;
use crate::proxy::tls13::complete_tls13_handshake;

/// Длина тега аутентификации для всех поддерживаемых AEAD-шифров.
const AEAD_TAG_LEN: usize = 16;

/// Адрес назначения для исходящего TCP-потока (домен или IP).
#[derive(Debug, Clone, PartialEq)]
pub enum TargetAddr {
    Domain(String),
    Ip(IpAddr),
}

/// Собирает запрос VLESS (версия 0): version(1) + UUID(16) + addons(1=0) +
/// command(1=TCP) + port(2, BE) + тип адреса + адрес.
pub fn build_vless_request(uuid: &Uuid, target: &TargetAddr, port: u16) -> Result<Vec<u8>> {
    let mut req = Vec::new();
    req.push(0x00); // версия протокола
    req.extend_from_slice(uuid.as_bytes());
    req.push(0x00); // длина блока addons
    req.push(0x01); // команда: TCP
    req.extend_from_slice(&port.to_be_bytes());
    encode_address(&mut req, target, AddressEncoding::Vless)?;
    Ok(req)
}

/// Собирает запрос Trojan: hex(SHA224(password)) + CRLF + CMD(CONNECT) +
/// SOCKS5-адрес + CRLF.
pub fn build_trojan_request(password: &str, target: &TargetAddr, port: u16) -> Result<Vec<u8>> {
    let mut hasher = Sha224::new();
    hasher.update(password.as_bytes());
    let digest = hasher.finalize();

    let mut req = Vec::with_capacity(64);
    req.extend_from_slice(hex_encode(&digest).as_bytes());
    req.extend_from_slice(b"\r\n");
    req.push(0x01); // CMD: CONNECT
    encode_address(&mut req, target, AddressEncoding::Socks5)?;
    req.extend_from_slice(&port.to_be_bytes());
    req.extend_from_slice(b"\r\n");
    Ok(req)
}

/// Собирает SOCKS5-подобный адрес назначения, используемый в первом
/// зашифрованном чанке Shadowsocks AEAD: ATYP + адрес + порт(2, BE).
fn build_socks_address(target: &TargetAddr, port: u16) -> Result<Vec<u8>> {
    let mut req = Vec::new();
    encode_address(&mut req, target, AddressEncoding::Socks5)?;
    req.extend_from_slice(&port.to_be_bytes());
    Ok(req)
}

/// Схема кодирования типа адреса: VLESS (1=IPv4, 2=домен, 3=IPv6) отличается
/// от SOCKS5/Trojan/Shadowsocks (1=IPv4, 3=домен, 4=IPv6).
enum AddressEncoding {
    Vless,
    Socks5,
}

fn encode_address(out: &mut Vec<u8>, target: &TargetAddr, scheme: AddressEncoding) -> Result<()> {
    match target {
        TargetAddr::Domain(domain) => {
            if domain.len() > 255 {
                return Err(anyhow!("доменное имя слишком длинное: {}", domain));
            }
            out.push(match scheme {
                AddressEncoding::Vless => 0x02,
                AddressEncoding::Socks5 => 0x03,
            });
            out.push(domain.len() as u8);
            out.extend_from_slice(domain.as_bytes());
        }
        TargetAddr::Ip(IpAddr::V4(ip)) => {
            out.push(0x01);
            out.extend_from_slice(&ip.octets());
        }
        TargetAddr::Ip(IpAddr::V6(ip)) => {
            out.push(match scheme {
                AddressEncoding::Vless => 0x03,
                AddressEncoding::Socks5 => 0x04,
            });
            out.extend_from_slice(&ip.octets());
        }
    }
    Ok(())
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Поддерживаемые методы шифрования Shadowsocks AEAD.
#[derive(Debug, Clone, Copy, PartialEq)]
enum SsMethod {
    Aes128Gcm,
    Aes256Gcm,
    ChaCha20IetfPoly1305,
}

impl SsMethod {
    fn parse(method: &str) -> Result<Self> {
        match method {
            "aes-128-gcm" => Ok(SsMethod::Aes128Gcm),
            "aes-256-gcm" => Ok(SsMethod::Aes256Gcm),
            "chacha20-ietf-poly1305" | "chacha20-poly1305" => Ok(SsMethod::ChaCha20IetfPoly1305),
            other => Err(anyhow!("неподдерживаемый метод Shadowsocks: {}", other)),
        }
    }

    fn key_len(&self) -> usize {
        match self {
            SsMethod::Aes128Gcm => 16,
            SsMethod::Aes256Gcm | SsMethod::ChaCha20IetfPoly1305 => 32,
        }
    }

    /// Длина соли в AEAD-2017 равна длине ключа.
    fn salt_len(&self) -> usize {
        self.key_len()
    }
}

/// Производный AEAD-шифр с конкретным подключевым материалом.
enum AeadCipher {
    Aes128Gcm(Aes128Gcm),
    Aes256Gcm(Aes256Gcm),
    ChaCha20Poly1305(ChaCha20Poly1305),
}

impl AeadCipher {
    fn new(method: SsMethod, key: &[u8]) -> Result<Self> {
        match method {
            SsMethod::Aes128Gcm => Aes128Gcm::new_from_slice(key)
                .map(AeadCipher::Aes128Gcm)
                .map_err(|e| anyhow!("неверный ключ AES-128-GCM: {}", e)),
            SsMethod::Aes256Gcm => Aes256Gcm::new_from_slice(key)
                .map(AeadCipher::Aes256Gcm)
                .map_err(|e| anyhow!("неверный ключ AES-256-GCM: {}", e)),
            SsMethod::ChaCha20IetfPoly1305 => ChaCha20Poly1305::new_from_slice(key)
                .map(AeadCipher::ChaCha20Poly1305)
                .map_err(|e| anyhow!("неверный ключ ChaCha20-Poly1305: {}", e)),
        }
    }

    fn encrypt(&self, nonce: &[u8; 12], plaintext: &[u8]) -> Result<Vec<u8>> {
        let nonce = aead::generic_array::GenericArray::from_slice(nonce);
        match self {
            AeadCipher::Aes128Gcm(c) => c.encrypt(nonce, plaintext),
            AeadCipher::Aes256Gcm(c) => c.encrypt(nonce, plaintext),
            AeadCipher::ChaCha20Poly1305(c) => c.encrypt(nonce, plaintext),
        }
        .map_err(|e| anyhow!("ошибка AEAD-шифрования: {}", e))
    }

    fn decrypt(&self, nonce: &[u8; 12], ciphertext: &[u8]) -> Result<Vec<u8>> {
        let nonce = aead::generic_array::GenericArray::from_slice(nonce);
        match self {
            AeadCipher::Aes128Gcm(c) => c.decrypt(nonce, ciphertext),
            AeadCipher::Aes256Gcm(c) => c.decrypt(nonce, ciphertext),
            AeadCipher::ChaCha20Poly1305(c) => c.decrypt(nonce, ciphertext),
        }
        .map_err(|e| anyhow!("ошибка AEAD-дешифрования: {}", e))
    }
}

/// Производит главный ключ из пароля по схеме OpenSSL `EVP_BytesToKey`
/// (используется Shadowsocks для получения ключа нужной длины из пароля).
fn evp_bytes_to_key(password: &str, key_len: usize) -> Vec<u8> {
    let mut key = Vec::with_capacity(key_len);
    let mut prev: Vec<u8> = Vec::new();

    while key.len() < key_len {
        let mut hasher = Md5::new();
        hasher.update(&prev);
        hasher.update(password.as_bytes());
        let digest = hasher.finalize();
        key.extend_from_slice(&digest);
        prev = digest.to_vec();
    }

    key.truncate(key_len);
    key
}

/// Производит подключ сессии из главного ключа и соли через HKDF-SHA1
/// с информационной строкой "ss-subkey" (Shadowsocks AEAD spec).
fn derive_subkey(master_key: &[u8], salt: &[u8], key_len: usize) -> Result<Vec<u8>> {
    let hk = Hkdf::<Sha1>::new(Some(salt), master_key);
    let mut subkey = vec![0u8; key_len];
    hk.expand(b"ss-subkey", &mut subkey)
        .map_err(|e| anyhow!("ошибка HKDF: {}", e))?;
    Ok(subkey)
}

/// Увеличивает 12-байтный nonce как little-endian счётчик (с переносом).
fn increment_nonce(nonce: &mut [u8; 12]) {
    for byte in nonce.iter_mut() {
        let (res, overflow) = byte.overflowing_add(1);
        *byte = res;
        if !overflow {
            break;
        }
    }
}

/// Шифратор/дешифратор потока Shadowsocks AEAD (AEAD-2017).
///
/// Каждое направление потока имеет собственную соль (генерируется при
/// первом вызове `seal`/получается из первых байт при первом вызове
/// `open`) и собственный счётчик nonce. Один чанк — это
/// `[len_sealed][payload_sealed]`, где `len_sealed` зашифрован отдельно от
/// `payload_sealed` с инкрементом nonce между ними.
pub struct ShadowsocksCipher {
    method: SsMethod,
    master_key: Vec<u8>,
    encrypt_cipher: Option<AeadCipher>,
    encrypt_nonce: [u8; 12],
    decrypt_cipher: Option<AeadCipher>,
    decrypt_nonce: [u8; 12],
}

impl ShadowsocksCipher {
    pub fn new(method: &str, password: &str) -> Result<Self> {
        let method = SsMethod::parse(method)?;
        let master_key = evp_bytes_to_key(password, method.key_len());

        Ok(Self {
            method,
            master_key,
            encrypt_cipher: None,
            encrypt_nonce: [0u8; 12],
            decrypt_cipher: None,
            decrypt_nonce: [0u8; 12],
        })
    }

    /// Шифрует один чанк payload (макс. 0xFFFF байт), при первом вызове
    /// генерирует случайную соль и добавляет её перед чанком.
    pub fn seal(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        if plaintext.len() > 0xFFFF {
            return Err(anyhow!("payload превышает максимальный размер чанка AEAD"));
        }

        let mut out = Vec::with_capacity(self.method.salt_len() + 2 + AEAD_TAG_LEN + plaintext.len() + AEAD_TAG_LEN);

        if self.encrypt_cipher.is_none() {
            let mut salt = vec![0u8; self.method.salt_len()];
            rand::thread_rng().fill_bytes(&mut salt);
            let subkey = derive_subkey(&self.master_key, &salt, self.method.key_len())?;
            self.encrypt_cipher = Some(AeadCipher::new(self.method, &subkey)?);
            out.extend_from_slice(&salt);
        }

        let cipher = self
            .encrypt_cipher
            .as_ref()
            .ok_or_else(|| anyhow!("шифр шифрования не инициализирован"))?;

        let len_bytes = (plaintext.len() as u16).to_be_bytes();
        let sealed_len = cipher.encrypt(&self.encrypt_nonce, &len_bytes)?;
        increment_nonce(&mut self.encrypt_nonce);

        let sealed_payload = cipher.encrypt(&self.encrypt_nonce, plaintext)?;
        increment_nonce(&mut self.encrypt_nonce);

        out.extend_from_slice(&sealed_len);
        out.extend_from_slice(&sealed_payload);
        Ok(out)
    }

    /// Дешифрует один чанк из начала `data`. Возвращает количество
    /// потреблённых байт и расшифрованный payload. При первом вызове
    /// ожидает, что `data` начинается с соли.
    pub fn open(&mut self, data: &[u8]) -> Result<(usize, Vec<u8>)> {
        let mut offset = 0;

        if self.decrypt_cipher.is_none() {
            let salt_len = self.method.salt_len();
            if data.len() < salt_len {
                return Err(anyhow!("недостаточно данных для соли Shadowsocks AEAD"));
            }
            let salt = &data[..salt_len];
            let subkey = derive_subkey(&self.master_key, salt, self.method.key_len())?;
            self.decrypt_cipher = Some(AeadCipher::new(self.method, &subkey)?);
            offset += salt_len;
        }

        let cipher = self
            .decrypt_cipher
            .as_ref()
            .ok_or_else(|| anyhow!("шифр дешифрования не инициализирован"))?;

        if data.len() < offset + 2 + AEAD_TAG_LEN {
            return Err(anyhow!("недостаточно данных для длины чанка"));
        }
        let sealed_len = &data[offset..offset + 2 + AEAD_TAG_LEN];
        let len_bytes = cipher.decrypt(&self.decrypt_nonce, sealed_len)?;
        increment_nonce(&mut self.decrypt_nonce);
        offset += 2 + AEAD_TAG_LEN;

        if len_bytes.len() < 2 {
            return Err(anyhow!("некорректная длина чанка после дешифрования"));
        }
        let payload_len = u16::from_be_bytes([len_bytes[0], len_bytes[1]]) as usize;

        if data.len() < offset + payload_len + AEAD_TAG_LEN {
            return Err(anyhow!("недостаточно данных для payload чанка"));
        }
        let sealed_payload = &data[offset..offset + payload_len + AEAD_TAG_LEN];
        let plaintext = cipher.decrypt(&self.decrypt_nonce, sealed_payload)?;
        increment_nonce(&mut self.decrypt_nonce);
        offset += payload_len + AEAD_TAG_LEN;

        Ok((offset, plaintext))
    }
}

/// Открывает TCP-соединение до прокси-сервера профиля и отправляет
/// протокольный хендшейк (VLESS request / Trojan auth / Shadowsocks AEAD
/// address request) для указанного адреса назначения.
pub struct ProxyConnector;

impl ProxyConnector {
    /// Таймаут на установление TCP-соединения с прокси-сервером.
    const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

    /// Подключается к `profile.server:profile.port` и выполняет хендшейк
    /// протокола профиля для соединения с `target:target_port`.
    /// Возвращает установленный TCP-поток, готовый к передаче данных.
    /// Для VLESS-профилей с полем `reality_public_key` используется
    /// полный TLS 1.3 / REALITY handshake вместо plain TCP.
    pub async fn connect(profile: &ProxyProfile, target: &TargetAddr, target_port: u16) -> Result<TcpStream> {
        let addr = format!("{}:{}", profile.server, profile.port);

        let tcp = timeout(Self::CONNECT_TIMEOUT, TcpStream::connect(&addr))
            .await
            .map_err(|_| anyhow!("таймаут подключения к {}", addr))?
            .map_err(|e| anyhow!("не удалось подключиться к {}: {}", addr, e))?;

        match profile.protocol {
            ProtocolType::Vless => {
                let uuid_str = profile
                    .username
                    .as_deref()
                    .ok_or_else(|| anyhow!("в профиле VLESS отсутствует UUID"))?;
                let uuid = Uuid::parse_str(uuid_str)
                    .map_err(|e| anyhow!("некорректный UUID VLESS: {}", e))?;
                let vless_req = build_vless_request(&uuid, target, target_port)?;

                if let Some(pbk_b64) = &profile.reality_public_key {
                    // ── VLESS + REALITY path ──────────────────────────────────
                    let server_pubkey = parse_reality_pubkey(pbk_b64)?;
                    let short_id = parse_reality_short_id(profile.reality_short_id.as_deref())?;
                    let sni = profile.sni.as_deref().unwrap_or(&profile.server);
                    let hello = build_and_seal_client_hello(sni, &server_pubkey, &short_id)?;

                    let mut tls = complete_tls13_handshake(tcp, hello).await?;
                    tls.send_app_data(&vless_req).await?;
                    return Ok(tls.into_inner());
                }

                // ── Plain VLESS path ──────────────────────────────────────────
                let mut stream = tcp;
                stream.write_all(&vless_req).await?;
                stream.flush().await?;
                Ok(stream)
            }
            ProtocolType::Trojan => {
                let password = profile
                    .password
                    .as_deref()
                    .ok_or_else(|| anyhow!("в профиле Trojan отсутствует пароль"))?;
                let request = build_trojan_request(password, target, target_port)?;
                let mut stream = tcp;
                stream.write_all(&request).await?;
                stream.flush().await?;
                Ok(stream)
            }
            ProtocolType::Shadowsocks => {
                let method = profile
                    .username
                    .as_deref()
                    .ok_or_else(|| anyhow!("в профиле Shadowsocks отсутствует метод шифрования"))?;
                let password = profile
                    .password
                    .as_deref()
                    .ok_or_else(|| anyhow!("в профиле Shadowsocks отсутствует пароль"))?;

                let mut cipher = ShadowsocksCipher::new(method, password)?;
                let address_request = build_socks_address(target, target_port)?;
                let sealed = cipher.seal(&address_request)?;
                let mut stream = tcp;
                stream.write_all(&sealed).await?;
                stream.flush().await?;
                Ok(stream)
            }
        }
    }

    /// Измеряет время установления соединения и выполнения хендшейка
    /// (используется для отображения "ping" профиля в UI).
    pub async fn measure_latency(profile: &ProxyProfile) -> Result<u64> {
        let start = Instant::now();
        let target = TargetAddr::Domain("www.gstatic.com".to_string());
        let _stream = Self::connect(profile, &target, 443).await?;
        Ok(start.elapsed().as_millis() as u64)
    }
}

// ─── REALITY parameter helpers ───────────────────────────────────────────────

/// Decodes a base64url X25519 public key (`pbk` field) into 32 bytes.
fn parse_reality_pubkey(b64: &str) -> Result<[u8; 32]> {
    use base64::Engine as _;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(b64)
        .map_err(|e| anyhow!("REALITY pbk base64 decode: {}", e))?;
    if bytes.len() != 32 {
        return Err(anyhow!("REALITY pbk must be 32 bytes, got {}", bytes.len()));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// Decodes a hex short_id (`sid` field, up to 8 bytes) into bytes.
fn parse_reality_short_id(sid: Option<&str>) -> Result<Vec<u8>> {
    let sid = match sid {
        None | Some("") => return Ok(vec![]),
        Some(s) => s,
    };
    if sid.len() % 2 != 0 || sid.len() > 16 {
        return Err(anyhow!("REALITY sid must be 0–8 hex bytes, got {:?}", sid));
    }
    (0..sid.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&sid[i..i + 2], 16).map_err(|e| anyhow!("sid hex: {}", e)))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;
    use std::net::Ipv4Addr;
    use tokio::io::AsyncReadExt;
    use tokio::net::TcpListener;

    fn vless_profile(server: String, port: u16, uuid: &Uuid) -> ProxyProfile {
        ProxyProfile {
            id: "vless-test".to_string(),
            name: "VLESS Test".to_string(),
            url: String::new(),
            protocol: ProtocolType::Vless,
            server,
            port,
            username: Some(uuid.to_string()),
            password: None,
            reality_public_key: None,
            reality_short_id: None,
            sni: None,
            flow: None,
            fingerprint: None,
        }
    }

    fn trojan_profile(server: String, port: u16, password: &str) -> ProxyProfile {
        ProxyProfile {
            id: "trojan-test".to_string(),
            name: "Trojan Test".to_string(),
            url: String::new(),
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
        }
    }

    fn shadowsocks_profile(server: String, port: u16, method: &str, password: &str) -> ProxyProfile {
        ProxyProfile {
            id: "ss-test".to_string(),
            name: "SS Test".to_string(),
            url: String::new(),
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
        }
    }

    #[test]
    fn test_build_vless_request_domain() {
        let uuid = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap();
        let target = TargetAddr::Domain("example.com".to_string());

        let req = build_vless_request(&uuid, &target, 443).unwrap();

        assert_eq!(req[0], 0x00); // версия
        assert_eq!(&req[1..17], uuid.as_bytes()); // UUID
        assert_eq!(req[17], 0x00); // addons
        assert_eq!(req[18], 0x01); // TCP
        assert_eq!(&req[19..21], &443u16.to_be_bytes()); // порт
        assert_eq!(req[21], 0x02); // ATYP: домен
        assert_eq!(req[22], 11); // длина "example.com"
        assert_eq!(&req[23..34], b"example.com");
        assert_eq!(req.len(), 34);
    }

    #[test]
    fn test_build_vless_request_ipv4() {
        let uuid = Uuid::new_v4();
        let target = TargetAddr::Ip(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));

        let req = build_vless_request(&uuid, &target, 53).unwrap();

        assert_eq!(req[21], 0x01); // ATYP: IPv4
        assert_eq!(&req[22..26], &[8, 8, 8, 8]);
        assert_eq!(req.len(), 26);
    }

    #[test]
    fn test_build_trojan_request_format() {
        let target = TargetAddr::Domain("example.com".to_string());
        let req = build_trojan_request("my-password", &target, 443).unwrap();

        let mut hasher = Sha224::new();
        hasher.update(b"my-password");
        let expected_hash = hex_encode(&hasher.finalize());

        assert_eq!(&req[0..56], expected_hash.as_bytes());
        assert_eq!(&req[56..58], b"\r\n");
        assert_eq!(req[58], 0x01); // CMD: CONNECT
        assert_eq!(req[59], 0x03); // ATYP: домен
        assert_eq!(req[60], 11);
        assert_eq!(&req[61..72], b"example.com");
        assert_eq!(&req[72..74], &443u16.to_be_bytes());
        assert_eq!(&req[74..76], b"\r\n");
    }

    #[test]
    fn test_build_socks_address_ipv6() {
        let target = TargetAddr::Ip(IpAddr::V6("::1".parse().unwrap()));
        let req = build_socks_address(&target, 8080).unwrap();

        assert_eq!(req[0], 0x04); // ATYP: IPv6
        assert_eq!(req.len(), 1 + 16 + 2);
    }

    #[test]
    fn test_shadowsocks_cipher_roundtrip_aes_256_gcm() {
        let mut enc = ShadowsocksCipher::new("aes-256-gcm", "super-secret").unwrap();
        let mut dec = ShadowsocksCipher::new("aes-256-gcm", "super-secret").unwrap();

        let sealed1 = enc.seal(b"hello world").unwrap();
        let (consumed1, plain1) = dec.open(&sealed1).unwrap();
        assert_eq!(consumed1, sealed1.len());
        assert_eq!(plain1, b"hello world");

        // Второй чанк: соль уже не добавляется, nonce инкрементирован.
        let sealed2 = enc.seal(b"second chunk").unwrap();
        let (consumed2, plain2) = dec.open(&sealed2).unwrap();
        assert_eq!(consumed2, sealed2.len());
        assert_eq!(plain2, b"second chunk");
    }

    #[test]
    fn test_shadowsocks_cipher_roundtrip_chacha20() {
        let mut enc = ShadowsocksCipher::new("chacha20-ietf-poly1305", "another-secret").unwrap();
        let mut dec = ShadowsocksCipher::new("chacha20-ietf-poly1305", "another-secret").unwrap();

        let sealed = enc.seal(b"chacha payload").unwrap();
        let (consumed, plain) = dec.open(&sealed).unwrap();
        assert_eq!(consumed, sealed.len());
        assert_eq!(plain, b"chacha payload");
    }

    #[test]
    fn test_shadowsocks_cipher_roundtrip_aes_128_gcm() {
        let mut enc = ShadowsocksCipher::new("aes-128-gcm", "short-key-secret").unwrap();
        let mut dec = ShadowsocksCipher::new("aes-128-gcm", "short-key-secret").unwrap();

        let sealed = enc.seal(b"aes128 payload").unwrap();
        let (_, plain) = dec.open(&sealed).unwrap();
        assert_eq!(plain, b"aes128 payload");
    }

    #[test]
    fn test_shadowsocks_cipher_wrong_password_fails() {
        let mut enc = ShadowsocksCipher::new("aes-256-gcm", "correct-password").unwrap();
        let mut dec = ShadowsocksCipher::new("aes-256-gcm", "wrong-password").unwrap();

        let sealed = enc.seal(b"secret data").unwrap();
        assert!(dec.open(&sealed).is_err());
    }

    #[test]
    fn test_shadowsocks_unsupported_method() {
        let result = ShadowsocksCipher::new("rc4-md5", "password");
        assert!(result.is_err());
    }

    #[test]
    fn test_shadowsocks_seal_too_large() {
        let mut cipher = ShadowsocksCipher::new("aes-256-gcm", "password").unwrap();
        let large = vec![0u8; 0x10000];
        assert!(cipher.seal(&large).is_err());
    }

    #[tokio::test]
    async fn test_connector_vless_handshake_over_loopback() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let uuid = Uuid::new_v4();
        let profile = vless_profile(addr.ip().to_string(), addr.port(), &uuid);
        let target = TargetAddr::Domain("example.com".to_string());
        let expected = build_vless_request(&uuid, &target, 443).unwrap();

        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 1024];
            let n = socket.read(&mut buf).await.unwrap();
            buf.truncate(n);
            buf
        });

        let _stream = ProxyConnector::connect(&profile, &target, 443).await.unwrap();
        let received = server.await.unwrap();

        assert_eq!(received, expected);
    }

    #[tokio::test]
    async fn test_connector_trojan_handshake_over_loopback() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let profile = trojan_profile(addr.ip().to_string(), addr.port(), "trojan-password");
        let target = TargetAddr::Domain("example.org".to_string());
        let expected = build_trojan_request("trojan-password", &target, 8443).unwrap();

        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 1024];
            let n = socket.read(&mut buf).await.unwrap();
            buf.truncate(n);
            buf
        });

        let _stream = ProxyConnector::connect(&profile, &target, 8443).await.unwrap();
        let received = server.await.unwrap();

        assert_eq!(received, expected);
    }

    #[tokio::test]
    async fn test_connector_shadowsocks_handshake_over_loopback() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let profile = shadowsocks_profile(addr.ip().to_string(), addr.port(), "aes-256-gcm", "ss-password");
        let target = TargetAddr::Domain("example.net".to_string());
        let expected_address_request = build_socks_address(&target, 9000).unwrap();

        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 1024];
            let n = socket.read(&mut buf).await.unwrap();
            buf.truncate(n);

            let mut cipher = ShadowsocksCipher::new("aes-256-gcm", "ss-password").unwrap();
            let (_, plaintext) = cipher.open(&buf).unwrap();
            plaintext
        });

        let _stream = ProxyConnector::connect(&profile, &target, 9000).await.unwrap();
        let decrypted = server.await.unwrap();

        assert_eq!(decrypted, expected_address_request);
    }

    #[tokio::test]
    async fn test_connector_connection_refused() {
        // Порт 0 после bind+drop почти наверняка не прослушивается.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);

        let uuid = Uuid::new_v4();
        let profile = vless_profile(addr.ip().to_string(), addr.port(), &uuid);
        let target = TargetAddr::Domain("example.com".to_string());

        let result = ProxyConnector::connect(&profile, &target, 443).await;
        assert!(result.is_err());
    }

    /// Локальный тест против реальной подписки: читает `.local/local_subscription.txt`
    /// (в .gitignore, не коммитится) и пытается измерить latency для первого
    /// профиля. Если файла нет, тест молча пропускается. Запуск:
    /// `cargo test --lib proxy::connector -- --ignored --nocapture`.
    #[tokio::test]
    #[ignore = "требует локальный файл .local/local_subscription.txt с реальной подпиской"]
    async fn test_connector_against_local_subscription() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../.local/local_subscription.txt");

        let content = match std::fs::read_to_string(&path) {
            Ok(content) => content,
            Err(_) => return,
        };

        for line in content.lines().map(str::trim).filter(|l| !l.is_empty()) {
            let profile = match crate::config::parse_subscription_url(line) {
                Ok(profile) => profile,
                Err(e) => {
                    println!("SKIP (parse error): {} -> {}", line, e);
                    continue;
                }
            };

            match ProxyConnector::measure_latency(&profile).await {
                Ok(ping) => println!("OK   {} ({}:{}) -> {} ms", profile.name, profile.server, profile.port, ping),
                Err(e) => println!("FAIL {} ({}:{}) -> {}", profile.name, profile.server, profile.port, e),
            }
        }
    }

    // ── REALITY parameter helpers ──────────────────────────────────────────

    #[test]
    fn test_parse_reality_pubkey_valid() {
        // 32 zero bytes base64url-encoded (no padding)
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode([0u8; 32]);
        let key = parse_reality_pubkey(&b64).unwrap();
        assert_eq!(key, [0u8; 32]);
    }

    #[test]
    fn test_parse_reality_pubkey_wrong_length() {
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode([0u8; 16]); // too short
        assert!(parse_reality_pubkey(&b64).is_err());
    }

    #[test]
    fn test_parse_reality_pubkey_invalid_b64() {
        assert!(parse_reality_pubkey("not!!base64").is_err());
    }

    #[test]
    fn test_parse_reality_short_id_empty() {
        assert_eq!(parse_reality_short_id(None).unwrap(), Vec::<u8>::new());
        assert_eq!(parse_reality_short_id(Some("")).unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn test_parse_reality_short_id_valid() {
        assert_eq!(parse_reality_short_id(Some("abcd")).unwrap(), vec![0xab, 0xcd]);
        assert_eq!(parse_reality_short_id(Some("deadbeef01020304")).unwrap(),
            vec![0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04]);
    }

    #[test]
    fn test_parse_reality_short_id_too_long() {
        assert!(parse_reality_short_id(Some("aabbccddeeff00112233")).is_err()); // 10 bytes
    }

    #[test]
    fn test_parse_reality_short_id_odd_hex() {
        assert!(parse_reality_short_id(Some("abc")).is_err()); // odd length
    }
}
