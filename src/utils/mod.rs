use chrono::{DateTime, Utc};

pub mod logger;

#[derive(Debug, Clone)]
pub struct LogEntry {
    pub timestamp: DateTime<Utc>,
    pub level: LogLevel,
    pub source: String,
    pub message: String,
}

#[derive(Debug, Clone)]
pub enum LogLevel {
    Info,
    Warning,
    Error,
    Debug,
}

impl LogEntry {
    pub fn new(level: LogLevel, source: &str, message: &str) -> Self {
        let timestamp = Utc::now();
        
        Self {
            timestamp,
            level,
            source: source.to_string(),
            message: message.to_string(),
        }
    }

    fn level_str(&self) -> &'static str {
        match self.level {
            LogLevel::Info => "INFO",
            LogLevel::Warning => "WARN",
            LogLevel::Error => "ERROR",
            LogLevel::Debug => "DEBUG",
        }
    }

    pub fn format(&self) -> String {
        let time_str = self.timestamp.format("%H:%M:%S").to_string();
        format!("[{}] [{}] [{}] {}", time_str, self.level_str(), self.source, self.message)
    }

    pub fn to_log_line(&self) -> String {
        format!("[{}] [{}] {}", self.level_str(), self.source, self.message)
    }
}

pub fn get_formatted_log(level: LogLevel, source: &str, message: &str) -> String {
    let entry = LogEntry::new(level, source, message);
    entry.format()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_log_entry_creation() {
        let entry = LogEntry::new(LogLevel::Info, "DNS", "Test message");
        
        assert_eq!(entry.source, "DNS");
        assert_eq!(entry.message, "Test message");
    }

    #[test]
    fn test_log_format_info() {
        let entry = LogEntry::new(LogLevel::Info, "DNS", "Test message");
        
        assert!(entry.format().contains("INFO"));
    }

    #[test]
    fn test_log_format_error() {
        let entry = LogEntry::new(LogLevel::Error, "TUN", "Connection failed");
        
        assert!(entry.format().contains("ERROR"));
    }

    #[test]
    fn test_log_to_line() {
        let entry = LogEntry::new(LogLevel::Info, "DNS", "Test message");
        
        let line = entry.to_log_line();
        
        assert!(line.contains("[INFO]"));
        assert!(line.contains("Test message"));
    }

    #[test]
    fn test_get_formatted_log() {
        let formatted = get_formatted_log(LogLevel::Info, "DNS", "Test");
        
        assert!(formatted.contains("INFO"));
        assert!(formatted.contains("Test"));
    }
}
