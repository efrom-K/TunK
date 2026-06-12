use anyhow::Result;
use std::collections::HashMap;

/// Тип расширения TLS, содержащего Server Name Indication (SNI).
const EXTENSION_SERVER_NAME: u16 = 0x0000;

/// Тип имени "host_name" внутри расширения server_name.
const SERVER_NAME_TYPE_HOST_NAME: u8 = 0x00;

pub struct TlsSniffer {
    pub sniffed_domains: HashMap<u64, String>, // packet_offset -> domain
}

impl TlsSniffer {
    pub fn new() -> Self {
        Self {
            sniffed_domains: HashMap::new(),
        }
    }

    /// Разбирает TLS-пакет и, если это TLS Client Hello с расширением SNI,
    /// возвращает запрошенный домен. Все многобайтовые поля TLS передаются
    /// в network byte order (big-endian).
    pub fn analyze_tls_handshake(&self, data: &[u8]) -> Result<Option<String>, String> {
        // TLS record header: 1 байт тип записи + 2 байта версия + 2 байта длина = 5 байт
        if data.len() < 5 {
            return Err("Пакет слишком короткий для анализа TLS".to_string());
        }

        let record_type = data[0];
        if record_type != 0x16 {
            // Это не TLS handshake пакет, пропускаем
            return Ok(None);
        }

        let record_length = u16::from_be_bytes([data[3], data[4]]) as usize;
        if data.len() < 5 + record_length {
            return Err("Недостаточно данных для анализа".to_string());
        }

        // Handshake header: 1 байт тип (0x01 = ClientHello) + 3 байта длина
        let handshake_start = 5;
        if data.len() < handshake_start + 4 {
            return Ok(None);
        }

        if data[handshake_start] != 0x01 {
            // Не ClientHello
            return Ok(None);
        }

        let mut offset = handshake_start + 4;

        // client_version (2 байта)
        if offset + 2 > data.len() {
            return Ok(None);
        }
        let tls_version = u16::from_be_bytes([data[offset], data[offset + 1]]);
        if tls_version < 0x0301 {
            return Ok(None); // Не поддерживаемая версия TLS
        }
        offset += 2;

        // random (32 байта)
        offset += 32;
        if offset > data.len() {
            return Ok(None);
        }

        // session_id
        if offset >= data.len() {
            return Ok(None);
        }
        let session_id_len = data[offset] as usize;
        offset += 1 + session_id_len;
        if offset > data.len() {
            return Ok(None);
        }

        // cipher_suites
        if offset + 2 > data.len() {
            return Ok(None);
        }
        let cipher_suites_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
        offset += 2 + cipher_suites_len;
        if offset > data.len() {
            return Ok(None);
        }

        // compression_methods
        if offset >= data.len() {
            return Ok(None);
        }
        let compression_methods_len = data[offset] as usize;
        offset += 1 + compression_methods_len;
        if offset > data.len() {
            return Ok(None);
        }

        // extensions
        if offset + 2 > data.len() {
            return Ok(None);
        }
        let extensions_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
        offset += 2;
        let extensions_end = (offset + extensions_len).min(data.len());

        while offset + 4 <= extensions_end {
            let extension_type = u16::from_be_bytes([data[offset], data[offset + 1]]);
            let extension_len = u16::from_be_bytes([data[offset + 2], data[offset + 3]]) as usize;
            let extension_data_start = offset + 4;
            let extension_data_end = extension_data_start + extension_len;

            if extension_data_end > extensions_end {
                break;
            }

            if extension_type == EXTENSION_SERVER_NAME {
                if let Some(domain) = parse_server_name_extension(&data[extension_data_start..extension_data_end]) {
                    return Ok(Some(domain));
                }
            }

            offset = extension_data_end;
        }

        Ok(None)
    }

    pub fn sniff_packet(&mut self, packet_offset: u64, domain: String) -> Result<(), String> {
        self.sniffed_domains.insert(packet_offset, domain);
        Ok(())
    }

    pub fn get_sniffed_domain(&self, packet_offset: u64) -> Option<&String> {
        self.sniffed_domains.get(&packet_offset)
    }

    pub fn clear_cache(&mut self) {
        self.sniffed_domains.clear();
    }

    pub fn get_stats(&self) -> usize {
        self.sniffed_domains.len()
    }
}

/// Разбирает содержимое расширения `server_name` (RFC 6066) и возвращает
/// первое имя хоста типа `host_name`.
fn parse_server_name_extension(data: &[u8]) -> Option<String> {
    // server_name_list: 2 байта длина списка
    if data.len() < 2 {
        return None;
    }

    let list_len = u16::from_be_bytes([data[0], data[1]]) as usize;
    let list_end = (2 + list_len).min(data.len());
    let mut offset = 2;

    while offset + 3 <= list_end {
        let name_type = data[offset];
        let name_len = u16::from_be_bytes([data[offset + 1], data[offset + 2]]) as usize;
        let name_start = offset + 3;
        let name_end = name_start + name_len;

        if name_end > list_end {
            break;
        }

        if name_type == SERVER_NAME_TYPE_HOST_NAME {
            return String::from_utf8(data[name_start..name_end].to_vec()).ok();
        }

        offset = name_end;
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Собирает корректный TLS Client Hello пакет (TLS 1.2) с расширением SNI,
    /// содержащим указанный домен.
    fn build_client_hello_with_sni(domain: &str) -> Vec<u8> {
        let domain_bytes = domain.as_bytes();

        // server_name_list: 1 байт тип + 2 байта длина + имя хоста
        let mut server_name_list = Vec::new();
        server_name_list.push(SERVER_NAME_TYPE_HOST_NAME);
        server_name_list.extend_from_slice(&(domain_bytes.len() as u16).to_be_bytes());
        server_name_list.extend_from_slice(domain_bytes);

        // расширение server_name: 2 байта длина списка + список
        let mut sni_extension_data = Vec::new();
        sni_extension_data.extend_from_slice(&(server_name_list.len() as u16).to_be_bytes());
        sni_extension_data.extend_from_slice(&server_name_list);

        let mut extensions = Vec::new();
        extensions.extend_from_slice(&EXTENSION_SERVER_NAME.to_be_bytes());
        extensions.extend_from_slice(&(sni_extension_data.len() as u16).to_be_bytes());
        extensions.extend_from_slice(&sni_extension_data);

        build_client_hello(&extensions)
    }

    /// Собирает TLS Client Hello пакет с произвольным заранее закодированным блоком расширений.
    fn build_client_hello(extensions: &[u8]) -> Vec<u8> {
        let mut handshake_body = Vec::new();
        handshake_body.extend_from_slice(&[0x03, 0x03]); // client_version: TLS 1.2
        handshake_body.extend_from_slice(&[0u8; 32]); // random
        handshake_body.push(0x00); // session_id_len = 0
        handshake_body.extend_from_slice(&[0x00, 0x02]); // cipher_suites_len = 2
        handshake_body.extend_from_slice(&[0x00, 0x2f]); // TLS_RSA_WITH_AES_128_CBC_SHA
        handshake_body.push(0x01); // compression_methods_len = 1
        handshake_body.push(0x00); // compression method: null
        handshake_body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        handshake_body.extend_from_slice(extensions);

        let mut handshake = Vec::new();
        handshake.push(0x01); // ClientHello
        let len = handshake_body.len() as u32;
        handshake.extend_from_slice(&[(len >> 16) as u8, (len >> 8) as u8, len as u8]);
        handshake.extend_from_slice(&handshake_body);

        let mut record = Vec::new();
        record.push(0x16); // TLS handshake record
        record.extend_from_slice(&[0x03, 0x01]); // record version
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);

        record
    }

    #[test]
    fn test_sni_extraction_from_real_client_hello() {
        let sniffer = TlsSniffer::new();
        let domain = "example.com";

        let packet = build_client_hello_with_sni(domain);
        let result = sniffer.analyze_tls_handshake(&packet).unwrap();

        assert_eq!(result, Some(domain.to_string()));
    }

    #[test]
    fn test_sni_extraction_with_preceding_extension() {
        let sniffer = TlsSniffer::new();
        let domain = "github.com";

        // Расширение ec_point_formats перед server_name
        let mut extensions = Vec::new();
        extensions.extend_from_slice(&[0x00, 0x0b]); // ec_point_formats
        extensions.extend_from_slice(&[0x00, 0x02]); // длина = 2
        extensions.extend_from_slice(&[0x01, 0x00]); // данные

        let mut server_name_list = Vec::new();
        server_name_list.push(SERVER_NAME_TYPE_HOST_NAME);
        server_name_list.extend_from_slice(&(domain.len() as u16).to_be_bytes());
        server_name_list.extend_from_slice(domain.as_bytes());

        let mut sni_extension_data = Vec::new();
        sni_extension_data.extend_from_slice(&(server_name_list.len() as u16).to_be_bytes());
        sni_extension_data.extend_from_slice(&server_name_list);

        extensions.extend_from_slice(&EXTENSION_SERVER_NAME.to_be_bytes());
        extensions.extend_from_slice(&(sni_extension_data.len() as u16).to_be_bytes());
        extensions.extend_from_slice(&sni_extension_data);

        let packet = build_client_hello(&extensions);
        let result = sniffer.analyze_tls_handshake(&packet).unwrap();

        assert_eq!(result, Some(domain.to_string()));
    }

    #[test]
    fn test_client_hello_without_sni_extension() {
        let sniffer = TlsSniffer::new();

        // Расширение ec_point_formats без server_name
        let mut extensions = Vec::new();
        extensions.extend_from_slice(&[0x00, 0x0b]);
        extensions.extend_from_slice(&[0x00, 0x02]);
        extensions.extend_from_slice(&[0x01, 0x00]);

        let packet = build_client_hello(&extensions);
        let result = sniffer.analyze_tls_handshake(&packet).unwrap();

        assert_eq!(result, None);
    }

    #[test]
    fn test_tls_record_type_detection() {
        let sniffer = TlsSniffer::new();

        // TLS record type 0x16, record body length = 0
        let tls_header = vec![0x16, 0x03, 0x03, 0x00, 0x00];

        assert!(sniffer.analyze_tls_handshake(&tls_header).is_ok());
    }

    #[test]
    fn test_non_tls_packet_detection() {
        let sniffer = TlsSniffer::new();

        // TCP packet (not TLS)
        let tcp_data = vec![0x14, 0x03, 0x03, 0x00, 0x2e];

        assert!(sniffer.analyze_tls_handshake(&tcp_data).unwrap().is_none());
    }

    #[test]
    fn test_short_packet_handling() {
        let sniffer = TlsSniffer::new();

        // Too short packet
        let short_data = vec![0x16];

        assert!(sniffer.analyze_tls_handshake(&short_data).is_err());
    }

    #[test]
    fn test_sniffed_domains_storage() {
        let mut sniffer = TlsSniffer::new();

        let domain = "example.com".to_string();
        let offset: u64 = 100;

        assert!(sniffer.sniff_packet(offset, domain.clone()).is_ok());

        assert_eq!(sniffer.get_sniffed_domain(offset), Some(&domain));
    }

    #[test]
    fn test_clear_cache() {
        let mut sniffer = TlsSniffer::new();

        let domain1 = "example.com".to_string();
        let offset1: u64 = 100;

        assert!(sniffer.sniff_packet(offset1, domain1).is_ok());

        assert_eq!(sniffer.get_stats(), 1);

        sniffer.clear_cache();

        assert_eq!(sniffer.get_stats(), 0);
    }

    #[test]
    fn test_tls_version_check() {
        let sniffer = TlsSniffer::new();

        // TLS 1.2 (0x0303), record body length = 0
        let tls_1_2_header = vec![0x16, 0x03, 0x03, 0x00, 0x00];

        assert!(sniffer.analyze_tls_handshake(&tls_1_2_header).is_ok());
    }

    #[test]
    fn test_old_tls_version() {
        let sniffer = TlsSniffer::new();

        // TLS 1.0 (0x0301) - record body length = 0
        let tls_1_0_header = vec![0x16, 0x03, 0x01, 0x00, 0x00];

        assert!(sniffer.analyze_tls_handshake(&tls_1_0_header).is_ok());
    }

    #[test]
    fn test_unsupported_tls_version() {
        let sniffer = TlsSniffer::new();

        // TLS 1.3 (0x0304) - record body length = 0
        let tls_1_3_header = vec![0x16, 0x03, 0x04, 0x00, 0x00];

        assert!(sniffer.analyze_tls_handshake(&tls_1_3_header).is_ok());
    }
}
