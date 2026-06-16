//! Построение TLS 1.3 ClientHello с REALITY-аутентификацией (Xray-core `transport/internet/reality`).
//!
//! REALITY встраивает аутентифицированный payload в поле `legacy_session_id` обычного
//! TLS 1.3 ClientHello. Сервер, владеющий приватным ключом REALITY, проверяет и
//! расшифровывает это поле и работает как VLESS-проксі; для всех остальных наблюдателей
//! соединение выглядит как обычный TLS-хендшейк к домену камуфляжа (`sni`).

use aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key};
use anyhow::{anyhow, Result};
use hkdf::Hkdf;
use rand::RngCore;
use sha2::Sha256;

/// Тип хэндшейк-сообщения ClientHello (RFC 8446 §4).
const HANDSHAKE_TYPE_CLIENT_HELLO: u8 = 0x01;

/// `legacy_version` поля ClientHello — всегда TLS 1.2 для совместимости (реальная версия в extension).
const LEGACY_VERSION_TLS12: u16 = 0x0303;

/// TLS 1.3 cipher suites, которые поддерживает клиент.
const CIPHER_SUITES: [u16; 3] = [
    0x1301, // TLS_AES_128_GCM_SHA256
    0x1302, // TLS_AES_256_GCM_SHA384
    0x1303, // TLS_CHACHA20_POLY1305_SHA256
];

/// Группы для key_share / supported_groups (только X25519).
const GROUP_X25519: u16 = 0x001d;

/// supported_versions: TLS 1.3.
const TLS1_3_VERSION: u16 = 0x0304;

/// signature_algorithms, ожидаемые большинством серверов TLS 1.3.
const SIGNATURE_ALGORITHMS: [u16; 8] = [
    0x0403, // ecdsa_secp256r1_sha256
    0x0804, // rsa_pss_rsae_sha256
    0x0401, // rsa_pkcs1_sha256
    0x0503, // ecdsa_secp384r1_sha384
    0x0805, // rsa_pss_rsae_sha384
    0x0501, // rsa_pkcs1_sha384
    0x0806, // rsa_pss_rsae_sha512
    0x0807, // ed25519
];

/// Версия Xray-core, встраиваемая в первые байты `session_id` (см. `reality.go`).
/// Значение не критично для большинства серверов (используется для проверки совместимости).
const XRAY_CORE_VERSION: (u8, u8, u8) = (25, 9, 11);

/// Смещение поля `session_id` (32 байта) внутри сериализованного сообщения ClientHello.
/// Раскладка: handshake header (1+3) + legacy_version (2) + random (32) + session_id_length (1) = 39.
const SESSION_ID_OFFSET: usize = 39;
const SESSION_ID_LEN: usize = 32;

/// Результат построения ClientHello с примененной REALITY-аутентификацией.
pub struct RealityClientHello {
    /// Полные байты хэндшейк-сообщения ClientHello (включая 4-байтовый заголовок),
    /// с зашифрованным полем `session_id`.
    pub raw: Vec<u8>,
    /// `Random` поле ClientHello (32 байта) — потребуется для TLS 1.3 key schedule.
    pub client_random: [u8; 32],
    /// Приватный эфемерный X25519 ключ, использованный в key_share — нужен повторно
    /// для key schedule TLS 1.3 (server's key_share ECDH), т.к. он совпадает с ключом,
    /// которым была вычислена `auth_key`.
    pub ephemeral_private_key: [u8; 32],
    /// REALITY `AuthKey` = HKDF-SHA256(salt=Random[..20], ikm=ECDH(ephemeral, server_pbk), info="REALITY").
    /// Используется позже для верификации сертификата сервера (HMAC-SHA512).
    pub auth_key: [u8; 32],
}

/// Строит ClientHello для заданного домена камуфляжа (`sni`), генерирует эфемерную
/// X25519 пару, применяет REALITY-аутентификацию (шифрует `session_id`) с публичным
/// ключом сервера `server_public_key` (`pbk`) и коротким идентификатором `short_id` (`sid`).
pub fn build_and_seal_client_hello(
    sni: &str,
    server_public_key: &[u8; 32],
    short_id: &[u8],
) -> Result<RealityClientHello> {
    if short_id.len() > 8 {
        return Err(anyhow!(
            "REALITY short_id длиннее 8 байт: {} байт",
            short_id.len()
        ));
    }

    let mut rng = rand::thread_rng();

    let mut ephemeral_private_key = [0u8; 32];
    rng.fill_bytes(&mut ephemeral_private_key);
    let ephemeral_public_key =
        x25519_dalek::x25519(ephemeral_private_key, x25519_dalek::X25519_BASEPOINT_BYTES);

    let mut client_random = [0u8; 32];
    rng.fill_bytes(&mut client_random);

    let mut raw = build_client_hello_bytes(sni, &client_random, &ephemeral_public_key);

    let auth_key = seal_session_id(
        &mut raw,
        &client_random,
        &ephemeral_private_key,
        server_public_key,
        short_id,
    )?;

    Ok(RealityClientHello {
        raw,
        client_random,
        ephemeral_private_key,
        auth_key,
    })
}

/// Шифрует поле `session_id` сообщения `raw` по алгоритму REALITY и возвращает `AuthKey`.
///
/// Шаги (см. `transport/internet/reality/reality.go`):
/// 1. `AuthKey = ECDH(ephemeral_private_key, server_public_key)`.
/// 2. `AuthKey = HKDF-SHA256(salt=client_random[..20], ikm=AuthKey, info="REALITY")` (32 байта).
/// 3. Plaintext = первые 16 байт `session_id`: версия Xray-core (3 байта) + reserved (1 байт) +
///    big-endian unix timestamp (4 байта) + `short_id` (до 8 байт, остаток — нули).
/// 4. `AEAD = AES-256-GCM(key=AuthKey)`, `nonce = client_random[20..32]`,
///    `aad = raw` (с `session_id`, всё ещё состоящим из 32 нулевых байт).
/// 5. Результат шифрования (16 байт ciphertext + 16 байт тег = 32 байта) записывается
///    обратно в поле `session_id`.
fn seal_session_id(
    raw: &mut [u8],
    client_random: &[u8; 32],
    ephemeral_private_key: &[u8; 32],
    server_public_key: &[u8; 32],
    short_id: &[u8],
) -> Result<[u8; 32]> {
    let shared_secret = x25519_dalek::x25519(*ephemeral_private_key, *server_public_key);

    let hk = Hkdf::<Sha256>::new(Some(&client_random[..20]), &shared_secret);
    let mut auth_key = [0u8; 32];
    hk.expand(b"REALITY", &mut auth_key)
        .map_err(|e| anyhow!("Не удалось вычислить REALITY AuthKey через HKDF: {}", e))?;

    let mut session_id_plain = [0u8; 16];
    session_id_plain[0] = XRAY_CORE_VERSION.0;
    session_id_plain[1] = XRAY_CORE_VERSION.1;
    session_id_plain[2] = XRAY_CORE_VERSION.2;
    session_id_plain[3] = 0; // reserved

    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| anyhow!("Некорректное системное время: {}", e))?
        .as_secs() as u32;
    session_id_plain[4..8].copy_from_slice(&timestamp.to_be_bytes());
    session_id_plain[8..8 + short_id.len()].copy_from_slice(short_id);

    // AAD — полное сообщение ClientHello с session_id, всё ещё равным 32 нулевым байтам.
    let aad = raw.to_vec();

    let cipher = Aes256Gcm::new(&Key::<Aes256Gcm>::from(auth_key));
    let nonce = aes_gcm::Nonce::from_slice(&client_random[20..32]);

    let ciphertext = cipher
        .encrypt(
            nonce,
            Payload {
                msg: &session_id_plain,
                aad: &aad,
            },
        )
        .map_err(|e| anyhow!("Не удалось зашифровать REALITY session_id: {}", e))?;

    raw[SESSION_ID_OFFSET..SESSION_ID_OFFSET + SESSION_ID_LEN].copy_from_slice(&ciphertext);

    Ok(auth_key)
}

/// Сериализует TLS 1.3 ClientHello (полное хэндшейк-сообщение, включая 4-байтовый заголовок)
/// с `session_id`, временно равным 32 нулевым байтам (заполняется позже `seal_session_id`).
fn build_client_hello_bytes(sni: &str, client_random: &[u8; 32], key_share_pub: &[u8; 32]) -> Vec<u8> {
    let mut body = Vec::new();

    body.extend_from_slice(&LEGACY_VERSION_TLS12.to_be_bytes());
    body.extend_from_slice(client_random);

    body.push(SESSION_ID_LEN as u8);
    body.extend(std::iter::repeat(0u8).take(SESSION_ID_LEN));

    let mut cipher_suites_bytes = Vec::new();
    for suite in CIPHER_SUITES {
        cipher_suites_bytes.extend_from_slice(&suite.to_be_bytes());
    }
    body.extend_from_slice(&(cipher_suites_bytes.len() as u16).to_be_bytes());
    body.extend(cipher_suites_bytes);

    // legacy_compression_methods: только "null" (0x00).
    body.push(1);
    body.push(0);

    let extensions = build_extensions(sni, key_share_pub);
    body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    body.extend(extensions);

    let mut raw = Vec::with_capacity(4 + body.len());
    raw.push(HANDSHAKE_TYPE_CLIENT_HELLO);
    let len = body.len() as u32;
    raw.extend_from_slice(&len.to_be_bytes()[1..]); // 3-байтовая длина (big-endian)
    raw.extend(body);

    raw
}

/// Сериализует блок extensions ClientHello: `server_name`, `supported_groups`,
/// `signature_algorithms`, `supported_versions`, `key_share`.
fn build_extensions(sni: &str, key_share_pub: &[u8; 32]) -> Vec<u8> {
    let mut extensions = Vec::new();

    write_extension(&mut extensions, 0x0000, &build_server_name_extension(sni));
    write_extension(&mut extensions, 0x000a, &build_supported_groups_extension());
    write_extension(&mut extensions, 0x000d, &build_signature_algorithms_extension());
    write_extension(&mut extensions, 0x002b, &build_supported_versions_extension());
    write_extension(&mut extensions, 0x0033, &build_key_share_extension(key_share_pub));

    extensions
}

/// Дописывает extension вида `[ext_type: u16][length: u16][data]` в `out`.
fn write_extension(out: &mut Vec<u8>, ext_type: u16, data: &[u8]) {
    out.extend_from_slice(&ext_type.to_be_bytes());
    out.extend_from_slice(&(data.len() as u16).to_be_bytes());
    out.extend_from_slice(data);
}

/// `server_name` extension (SNI), RFC 6066 §3.
fn build_server_name_extension(sni: &str) -> Vec<u8> {
    let host_name = sni.as_bytes();

    let mut server_name_entry = Vec::with_capacity(3 + host_name.len());
    server_name_entry.push(0x00); // name_type = host_name
    server_name_entry.extend_from_slice(&(host_name.len() as u16).to_be_bytes());
    server_name_entry.extend_from_slice(host_name);

    let mut data = Vec::with_capacity(2 + server_name_entry.len());
    data.extend_from_slice(&(server_name_entry.len() as u16).to_be_bytes());
    data.extend(server_name_entry);

    data
}

/// `supported_groups` extension, RFC 8446 §4.2.7 — только X25519.
fn build_supported_groups_extension() -> Vec<u8> {
    let mut data = Vec::new();
    data.extend_from_slice(&2u16.to_be_bytes());
    data.extend_from_slice(&GROUP_X25519.to_be_bytes());
    data
}

/// `signature_algorithms` extension, RFC 8446 §4.2.3.
fn build_signature_algorithms_extension() -> Vec<u8> {
    let mut data = Vec::new();
    data.extend_from_slice(&((SIGNATURE_ALGORITHMS.len() * 2) as u16).to_be_bytes());
    for alg in SIGNATURE_ALGORITHMS {
        data.extend_from_slice(&alg.to_be_bytes());
    }
    data
}

/// `supported_versions` extension, RFC 8446 §4.2.1 — только TLS 1.3.
fn build_supported_versions_extension() -> Vec<u8> {
    let mut data = Vec::new();
    data.push(2); // длина списка версий в байтах
    data.extend_from_slice(&TLS1_3_VERSION.to_be_bytes());
    data
}

/// `key_share` extension, RFC 8446 §4.2.8 — один X25519 KeyShareEntry.
fn build_key_share_extension(key_share_pub: &[u8; 32]) -> Vec<u8> {
    let mut entry = Vec::with_capacity(4 + 32);
    entry.extend_from_slice(&GROUP_X25519.to_be_bytes());
    entry.extend_from_slice(&(key_share_pub.len() as u16).to_be_bytes());
    entry.extend_from_slice(key_share_pub);

    let mut data = Vec::with_capacity(2 + entry.len());
    data.extend_from_slice(&(entry.len() as u16).to_be_bytes());
    data.extend(entry);

    data
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Фиктивный публичный ключ сервера для тестов (не настоящий REALITY `pbk`).
    const TEST_SERVER_PUBLIC_KEY: [u8; 32] = [0x42; 32];

    #[test]
    fn test_client_hello_starts_with_handshake_header() {
        let hello = build_and_seal_client_hello("example.com", &TEST_SERVER_PUBLIC_KEY, &[]).unwrap();

        assert_eq!(hello.raw[0], HANDSHAKE_TYPE_CLIENT_HELLO);

        let declared_len = u32::from_be_bytes([0, hello.raw[1], hello.raw[2], hello.raw[3]]) as usize;
        assert_eq!(declared_len, hello.raw.len() - 4);
    }

    #[test]
    fn test_client_hello_legacy_version_and_random() {
        let hello = build_and_seal_client_hello("example.com", &TEST_SERVER_PUBLIC_KEY, &[]).unwrap();

        let legacy_version = u16::from_be_bytes([hello.raw[4], hello.raw[5]]);
        assert_eq!(legacy_version, LEGACY_VERSION_TLS12);

        assert_eq!(&hello.raw[6..38], &hello.client_random[..]);
    }

    #[test]
    fn test_session_id_is_encrypted_not_zero() {
        let hello = build_and_seal_client_hello("example.com", &TEST_SERVER_PUBLIC_KEY, &[0xab, 0xcd]).unwrap();

        let session_id = &hello.raw[SESSION_ID_OFFSET..SESSION_ID_OFFSET + SESSION_ID_LEN];
        assert_ne!(session_id, &[0u8; SESSION_ID_LEN][..]);
    }

    #[test]
    fn test_auth_key_is_deterministic_for_same_inputs() {
        let mut client_random = [0u8; 32];
        client_random[0] = 1;
        let ephemeral_private_key = [7u8; 32];

        let mut raw = build_client_hello_bytes("example.com", &client_random, &[0u8; 32]);

        let auth_key_1 = seal_session_id(
            &mut raw.clone(),
            &client_random,
            &ephemeral_private_key,
            &TEST_SERVER_PUBLIC_KEY,
            &[],
        )
        .unwrap();

        let auth_key_2 = seal_session_id(
            &mut raw,
            &client_random,
            &ephemeral_private_key,
            &TEST_SERVER_PUBLIC_KEY,
            &[],
        )
        .unwrap();

        assert_eq!(auth_key_1, auth_key_2);
    }

    #[test]
    fn test_server_name_extension_contains_sni() {
        let hello = build_and_seal_client_hello("storage.example.net", &TEST_SERVER_PUBLIC_KEY, &[]).unwrap();

        assert!(hello.raw.windows("storage.example.net".len())
            .any(|window| window == "storage.example.net".as_bytes()));
    }

    #[test]
    fn test_short_id_too_long_is_rejected() {
        let result = build_and_seal_client_hello("example.com", &TEST_SERVER_PUBLIC_KEY, &[0u8; 9]);

        assert!(result.is_err());
    }

    #[test]
    fn test_key_share_extension_contains_ephemeral_public_key() {
        let hello = build_and_seal_client_hello("example.com", &TEST_SERVER_PUBLIC_KEY, &[]).unwrap();

        let ephemeral_public_key = x25519_dalek::x25519(
            hello.ephemeral_private_key,
            x25519_dalek::X25519_BASEPOINT_BYTES,
        );

        assert!(hello
            .raw
            .windows(32)
            .any(|window| window == ephemeral_public_key));
    }
}
