use anyhow::Result;

pub struct Obfuscator {
    pub mode: ObfuscationMode,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ObfuscationMode {
    ShadowsocksAead,
    Vless,
    Trojan,
}

impl Obfuscator {
    pub fn new(mode: ObfuscationMode) -> Self {
        Self { mode }
    }

    pub fn obfuscate_tcp(&self, data: &[u8]) -> Result<Vec<u8>, String> {
        match self.mode {
            ObfuscationMode::ShadowsocksAead => {
                // Shadowsocks AEAD обфускация
                let mut result = Vec::with_capacity(data.len() + 2);

                // Добавляем заголовок с длиной пакета (2 байта)
                let len_bytes: [u8; 2] = (data.len() as u16).to_le_bytes();
                result.extend_from_slice(&len_bytes);

                // Добавляем данные
                if data.len() <= 65535 {
                    result.extend_from_slice(data);
                } else {
                    return Err("Пакет слишком большой для Shadowsocks AEAD".to_string());
                }

                Ok(result)
            }
            ObfuscationMode::Vless => {
                // VLESS обфускация (на основе QUIC - 4 байта заголовка)
                let mut result = Vec::with_capacity(data.len() + 4);

                // Добавляем заголовок с длиной пакета (4 байта)
                let len_bytes: [u8; 4] = (data.len() as u32).to_le_bytes();
                result.extend_from_slice(&len_bytes);

                // Добавляем данные
                if data.len() <= 0xFFFFFFFF {
                    result.extend_from_slice(data);
                } else {
                    return Err("Пакет слишком большой для VLESS".to_string());
                }

                Ok(result)
            }
            ObfuscationMode::Trojan => {
                // Trojan обфускация (на основе HTTP/2 - 3 байта заголовка)
                let mut result = Vec::with_capacity(data.len() + 4);

                // Добавляем заголовок с длиной пакета (3 байта, у16 первые 3 байта)
                let len_bytes: [u8; 3] = [
                    (data.len() as u16) as u8,
                    ((data.len() >> 8) & 0xFF) as u8,
                    ((data.len() >> 16) & 0xFF) as u8,
                ];
                result.extend_from_slice(&len_bytes);

                // Добавляем данные
                if data.len() <= 0xFFFFFF {
                    result.extend_from_slice(data);
                } else {
                    return Err("Пакет слишком большой для Trojan".to_string());
                }

                Ok(result)
            }
        }
    }

    pub fn deobfuscate_tcp(&self, data: &[u8]) -> Result<Vec<u8>, String> {
        match self.mode {
            ObfuscationMode::ShadowsocksAead => {
                if data.len() < 2 {
                    return Err("Пакет слишком короткий для Shadowsocks AEAD".to_string());
                }

                let len = u16::from_le_bytes([data[0], data[1]]) as usize;

                if len > data.len() - 2 || len > 65535 {
                    return Err("Некорректная длина пакета".to_string());
                }

                let result_len = 2 + len as usize;
                let mut result = Vec::with_capacity(len);
                if result_len <= data.len() {
                    result.extend_from_slice(&data[2..result_len]);
                }

                Ok(result)
            }
            ObfuscationMode::Vless => {
                if data.len() < 4 {
                    return Err("Пакет слишком короткий для VLESS".to_string());
                }

                let len = u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as usize;

                if len > data.len() - 4 || len > 0xFFFFFFFF {
                    return Err("Некорректная длина пакета".to_string());
                }

                let result_len = 4 + len;
                let mut result = Vec::with_capacity(len);
                if result_len <= data.len() {
                    result.extend_from_slice(&data[4..result_len]);
                }

                Ok(result)
            }
            ObfuscationMode::Trojan => {
                if data.len() < 3 {
                    return Err("Пакет слишком короткий для Trojan".to_string());
                }

                let len = (data[0] as usize)
                    | ((data[1] as usize) << 8)
                    | ((data[2] as usize) << 16);

                if len > data.len() - 3 || len > 0xFFFFFF {
                    return Err("Некорректная длина пакета".to_string());
                }

                let result_len = 3 + len;
                let mut result = Vec::with_capacity(len);
                if result_len <= data.len() {
                    result.extend_from_slice(&data[3..result_len]);
                }

                Ok(result)
            }
        }
    }

    pub fn get_mode(&self) -> &ObfuscationMode {
        &self.mode
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shadowsocks_aead_obfuscation() {
        let obf = Obfuscator::new(ObfuscationMode::ShadowsocksAead);

        let original_data = b"Hello, World!";
        let obfuscated = obf.obfuscate_tcp(original_data).unwrap();

        let len_header = u16::from_le_bytes([obfuscated[0], obfuscated[1]]) as usize;
        assert_eq!(len_header, original_data.len());
        assert_eq!(obfuscated.len(), original_data.len() + 2);
    }

    #[test]
    fn test_shadowsocks_aead_deobfuscation() {
        let obf = Obfuscator::new(ObfuscationMode::ShadowsocksAead);

        let original_data = b"Hello, World!";
        let obfuscated = obf.obfuscate_tcp(original_data).unwrap();

        let deobfuscated = obf.deobfuscate_tcp(&obfuscated).unwrap();

        assert_eq!(deobfuscated, original_data);
    }

    #[test]
    fn test_vless_obfuscation() {
        let obf = Obfuscator::new(ObfuscationMode::Vless);

        let original_data = b"Hello, World!";
        let obfuscated = obf.obfuscate_tcp(original_data).unwrap();

        assert_eq!(obfuscated.len(), original_data.len() + 4);
    }

    #[test]
    fn test_vless_deobfuscation() {
        let obf = Obfuscator::new(ObfuscationMode::Vless);

        let original_data = b"Hello, World!";
        let obfuscated = obf.obfuscate_tcp(original_data).unwrap();

        let deobfuscated = obf.deobfuscate_tcp(&obfuscated).unwrap();

        assert_eq!(deobfuscated, original_data);
    }

    #[test]
    fn test_trojan_obfuscation() {
        let obf = Obfuscator::new(ObfuscationMode::Trojan);

        let original_data = b"Hello, World!";
        let obfuscated = obf.obfuscate_tcp(original_data).unwrap();

        assert_eq!(obfuscated.len(), original_data.len() + 3);
    }

    #[test]
    fn test_trojan_deobfuscation() {
        let obf = Obfuscator::new(ObfuscationMode::Trojan);

        let original_data = b"Hello, World!";
        let obfuscated = obf.obfuscate_tcp(original_data).unwrap();

        let deobfuscated = obf.deobfuscate_tcp(&obfuscated).unwrap();

        assert_eq!(deobfuscated, original_data);
    }

    #[test]
    fn test_deobfuscation_invalid_length() {
        let obf = Obfuscator::new(ObfuscationMode::ShadowsocksAead);

        // Пакет с неверной длиной заголовка
        let invalid_data: &[u8] = &b"Invalid"[..];

        assert!(obf.deobfuscate_tcp(invalid_data).is_err());
    }

    #[test]
    fn test_deobfuscation_empty() {
        let obf = Obfuscator::new(ObfuscationMode::ShadowsocksAead);

        // Пустой пакет
        let empty_data: &[u8] = &[];

        assert!(obf.deobfuscate_tcp(empty_data).is_err());
    }

    #[test]
    fn test_deobfuscation_too_short() {
        let obf = Obfuscator::new(ObfuscationMode::ShadowsocksAead);

        // Пакет слишком короткий
        let short_data: &[u8] = &b"Hi"[..];

        assert!(obf.deobfuscate_tcp(short_data).is_err());
    }

    #[test]
    fn test_obfuscation_large_packet() {
        let obf = Obfuscator::new(ObfuscationMode::ShadowsocksAead);

        // Пакет больше 65535 байт
        let large_data: Vec<u8> = vec![0u8; 70000];

        assert!(obf.obfuscate_tcp(&large_data).is_err());
    }

    #[test]
    fn test_obfuscation_mode() {
        let obf_ss = Obfuscator::new(ObfuscationMode::ShadowsocksAead);
        let obf_vless = Obfuscator::new(ObfuscationMode::Vless);

        assert_eq!(obf_ss.get_mode(), &ObfuscationMode::ShadowsocksAead);
        assert_eq!(obf_vless.get_mode(), &ObfuscationMode::Vless);
        assert_ne!(obf_ss.get_mode(), obf_vless.get_mode());
    }
}