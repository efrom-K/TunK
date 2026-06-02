use std::sync::{Arc, Mutex};
use anyhow::{Result, Context};
use chrono::{DateTime, Utc};

pub struct Logger {
    pub logs: Arc<Mutex<Vec<String>>>,
}

impl Logger {
    pub fn new() -> Self {
        Self {
            logs: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub fn log(&self, level: crate::utils::LogLevel, source: &str, message: &str) -> Result<(), String> {
        let formatted = crate::utils::get_formatted_log(level, source, message);
        
        self.logs.lock().map_err(|e| e.to_string())?;
        
        Ok(())
    }

    pub fn info(&self, source: &str, message: &str) -> Result<(), String> {
        let formatted = crate::utils::get_formatted_log(crate::utils::LogLevel::Info, source, message);
        
        self.logs.lock().map_err(|e| e.to_string())?;
        
        Ok(())
    }

    pub fn warning(&self, source: &str, message: &str) -> Result<(), String> {
        let formatted = crate::utils::get_formatted_log(crate::utils::LogLevel::Warning, source, message);
        
        self.logs.lock().map_err(|e| e.to_string())?;
        
        Ok(())
    }

    pub fn error(&self, source: &str, message: &str) -> Result<(), String> {
        let formatted = crate::utils::get_formatted_log(crate::utils::LogLevel::Error, source, message);
        
        self.logs.lock().map_err(|e| e.to_string())?;
        
        Ok(())
    }

    pub fn debug(&self, source: &str, message: &str) -> Result<(), String> {
        let formatted = crate::utils::get_formatted_log(crate::utils::LogLevel::Debug, source, message);
        
        self.logs.lock().map_err(|e| e.to_string())?;
        
        Ok(())
    }

    pub fn get_logs(&self) -> Vec<String> {
        self.logs.lock().unwrap_or_default().clone()
    }

    pub fn clear_logs(&self) {
        let mut logs = self.logs.lock().unwrap();
        logs.clear();
    }

    pub fn get_log_count(&self) -> usize {
        self.logs.lock().map(|l| l.len()).unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_logger_creation() {
        let logger = Logger::new();
        
        assert_eq!(logger.get_log_count(), 0);
    }

    #[tokio::test]
    async fn test_logger_info() {
        let logger = Logger::new();
        
        assert!(logger.info("DNS", "Test info").is_ok());
        
        assert_eq!(logger.get_log_count(), 1);
    }

    #[tokio::test]
    async fn test_logger_error() {
        let logger = Logger::new();
        
        assert!(logger.error("TUN", "Connection failed").is_ok());
        
        assert_eq!(logger.get_log_count(), 1);
    }

    #[tokio::test]
    async fn test_logger_clear() {
        let logger = Logger::new();
        
        logger.info("DNS", "Test info").unwrap();
        logger.error("TUN", "Error message").unwrap();
        
        assert_eq!(logger.get_log_count(), 2);
        
        logger.clear_logs();
        
        assert_eq!(logger.get_log_count(), 0);
    }

    #[tokio::test]
    async fn test_logger_concurrent_access() {
        let logger = Logger::new();
        
        let handles: Vec<_> = (0..10)
            .map(|_| tokio::spawn(async move {
                logger.info("DNS", "Concurrent info").unwrap_or_default();
            }))
            .collect();
        
        for handle in handles {
            let _ = handle.await;
        }
    }

    #[test]
    fn test_logger_get_logs() {
        let logger = Logger::new();
        
        assert!(logger.get_logs().is_empty());
    }
}
