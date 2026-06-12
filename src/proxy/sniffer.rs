use anyhow::Result;
use std::collections::HashMap;

pub struct TlsSniffer {
    pub sniffed_domains: HashMap<u64, String>, // packet_offset -> domain
}

impl TlsSniffer {
    pub fn new() -> Self {
        Self {
            sniffed_domains: HashMap::new(),
        }
    }

    pub fn analyze_tls_handshake(&self, data: &[u8]) -> Result<Option<String>, String> {
        // TLS Client Hello начинается с 0x16 (TLS record type)
        // Все многобайтовые поля TLS передаются в network byte order (big-endian)

        if data.len() < 5 {
            return Err("Пакет слишком короткий для анализа TLS".to_string());
        }

        let record_type = data[0];
        
        if record_type != 0x16 {
            // Это не TLS пакет, пропускаем
            return Ok(None);
        }

        // Проверяем длину заголовка TLS (минимум 5 байт)
        let content_length = u16::from_be_bytes([data[3], data[4]]) as usize;
        
        if data.len() < 5 + content_length as usize {
            return Err("Недостаточно данных для анализа".to_string());
        }

        // TLS Client Hello начинается после заголовка записи (байт 5)
        let client_hello_start = 5;
        
        if data.len() < client_hello_start + 2 {
            return Ok(None);
        }

        // Проверяем версию TLS (должна быть >= 3.1)
        let tls_version = u16::from_be_bytes([data[client_hello_start], data[client_hello_start + 1]]);
        
        if tls_version < 0x0301 {
            return Ok(None); // Не поддерживаемая версия TLS
        }

        // Ищем расширение SNI в Client Hello
        let mut offset = client_hello_start + 2;
        
        while offset < data.len() {
            if offset + 4 > data.len() {
                break;
            }

            let extension_type = u16::from_be_bytes([data[offset], data[offset + 1]]);
            
            // SNI имеет тип 0x0000 (или 0x0017 в некоторых реализациях)
            if extension_type == 0x0000 || extension_type == 0x0017 {
                let length = u16::from_be_bytes([data[offset + 2], data[offset + 3]]) as usize;
                
                if offset + 4 + length <= data.len() {
                    // Проверяем, является ли это списком имен (SNI List)
                        if data[offset + 4] == 0x01 { // SNI List
                            let list_length = u16::from_be_bytes([data[offset + 5], data[offset + 6]]) as usize;
                            
                            if offset + 7 + list_length <= data.len() {
                                let mut name_list_offset = offset + 7;
                                
                                while name_list_offset < data.len() && 
                                      name_list_offset + 3 <= data.len() {
                                    let name_type = u16::from_be_bytes([data[name_list_offset], data[name_list_offset + 1]]);
                                    
                                    if name_type == 0x00 { // Host Name
                                        let name_length = u16::from_be_bytes([data[name_list_offset + 2], data[name_list_offset + 3]]) as usize;
                                        
                                        if name_list_offset + 4 + name_length <= data.len() {
                                            let domain_start = name_list_offset + 4;
                                            let domain_end = domain_start + name_length;
                                            
                                            if domain_end <= data.len() {
                                                let domain_bytes: Vec<u8> = 
                                                    data[domain_start..domain_end].to_vec();
                                                
                                                match String::from_utf8(domain_bytes) {
                                                    Ok(domain) => {
                                                        return Ok(Some(domain));
                                                    }
                                                    Err(_) => {}
                                                }
                                            }
                                        }
                                    } else if name_type == 0x01 { // IP Address - пропускаем
                                        let _ = u16::from_be_bytes([data[name_list_offset + 2], data[name_list_offset + 3]]);
                                    }
                                    
                                    name_list_offset += 4;
                                }
                            } else {
                                offset += 4;
                            }
                        } else {
                            offset += 4;
                        }
                } else {
                    break;
                }
            } else if extension_type == 0x0017 { // SNI List (TLS 1.3)
                let length = u16::from_be_bytes([data[offset + 2], data[offset + 3]]) as usize;
                
                if offset + 4 + length <= data.len() {
                    let mut list_offset = offset + 4;
                    
                    while list_offset < data.len() && 
                          list_offset + 3 <= data.len() {
                        let name_type = u16::from_be_bytes([data[list_offset], data[list_offset + 1]]);
                        
                        if name_type == 0x00 { // Host Name
                            let name_length = u16::from_be_bytes([data[list_offset + 2], data[list_offset + 3]]) as usize;
                            
                            if list_offset + 4 + name_length <= data.len() {
                                let domain_start = list_offset + 4;
                                let domain_end = domain_start + name_length;
                                
                                if domain_end <= data.len() {
                                    let domain_bytes: Vec<u8> = 
                                        data[domain_start..domain_end].to_vec();
                                    
                                    match String::from_utf8(domain_bytes) {
                                        Ok(domain) => {
                                            return Ok(Some(domain));
                                        }
                                        Err(_) => {}
                                    }
                                }
                            }
                        } else if name_type == 0x01 { // IP Address - пропускаем
                            let _ = u16::from_be_bytes([data[list_offset + 2], data[list_offset + 3]]);
                        }
                        
                        list_offset += 4;
                    }
                } else {
                    break;
                }
            } else if extension_type == 0x00 { // Unknown extension - пропускаем
                offset += 4;
            } else {
                break;
            }
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

#[cfg(test)]
mod tests {
    use super::*;

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
        
        // TLS 1.0 (0x0301) - should be accepted, record body length = 0
        let tls_1_0_header = vec![0x16, 0x03, 0x01, 0x00, 0x00];

        assert!(sniffer.analyze_tls_handshake(&tls_1_0_header).is_ok());
    }

    #[test]
    fn test_unsupported_tls_version() {
        let sniffer = TlsSniffer::new();
        
        // TLS 1.3 (0x0304) - should be accepted, record body length = 0
        let tls_1_3_header = vec![0x16, 0x03, 0x04, 0x00, 0x00];

        assert!(sniffer.analyze_tls_handshake(&tls_1_3_header).is_ok());
    }
}