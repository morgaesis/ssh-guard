use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;
use std::collections::HashMap;
use anyhow::Result;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub timestamp: DateTime<Utc>,
    pub event_type: EventType,
    pub provider: String,
    pub model: String,
    pub request_id: String,
    pub user_id: Option<String>,
    pub success: bool,
    pub error: Option<String>,
    pub metadata: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EventType {
    ModelRequest,
    ModelResponse,
    CredentialAccess,
    SecretRedaction,
    RateLimit,
    Error,
}

pub struct AuditLogger {
    events: Arc<RwLock<Vec<AuditEvent>>>,
    config: AuditConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditConfig {
    pub log_file: Option<String>,
    pub log_level: LogLevel,
    pub retention_days: u32,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum LogLevel {
    Basic,
    Detailed,
    Debug,
}

impl AuditLogger {
    pub fn new(config: AuditConfig) -> Self {
        Self {
            events: Arc::new(RwLock::new(Vec::new())),
            config,
        }
    }

    pub async fn log_event(&self, mut event: AuditEvent) -> Result<()> {
        event.timestamp = Utc::now();

        // Add to in-memory store
        {
            let mut events = self.events.write().await;
            events.push(event.clone());
        }

        // Write to file if configured
        if let Some(log_file) = &self.config.log_file {
            let event_json = serde_json::to_string(&event)?;
            tokio::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(log_file)
                .await?
                .write_all(format!("{}\n", event_json).as_bytes())
                .await?;
        }

        Ok(())
    }

    pub async fn get_events(&self, filter: Option<EventFilter>) -> Vec<AuditEvent> {
        let events = self.events.read().await;
        match filter {
            Some(f) => events.iter()
                .filter(|e| f.matches(e))
                .cloned()
                .collect(),
            None => events.clone(),
        }
    }

    pub async fn cleanup_old_events(&self) -> Result<()> {
        let retention_cutoff = Utc::now() - chrono::Duration::days(self.config.retention_days as i64);

        let mut events = self.events.write().await;
        events.retain(|e| e.timestamp > retention_cutoff);

        Ok(())
    }
}

pub struct EventFilter {
    pub start_time: Option<DateTime<Utc>>,
    pub end_time: Option<DateTime<Utc>>,
    pub event_types: Option<Vec<EventType>>,
    pub provider: Option<String>,
    pub success_only: bool,
}

impl EventFilter {
    fn matches(&self, event: &AuditEvent) -> bool {
        // Check time range
        if let Some(start) = self.start_time {
            if event.timestamp < start {
                return false;
            }
        }
        if let Some(end) = self.end_time {
            if event.timestamp > end {
                return false;
            }
        }

        // Check event type
        if let Some(types) = &self.event_types {
            if !types.iter().any(|t| std::mem::discriminant(t) == std::mem::discriminant(&event.event_type)) {
                return false;
            }
        }

        // Check provider
        if let Some(provider) = &self.provider {
            if event.provider != *provider {
                return false;
            }
        }

        // Check success
        if self.success_only && !event.success {
            return false;
        }

        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn test_audit_logging() {
        let config = AuditConfig {
            log_file: None,
            log_level: LogLevel::Basic,
            retention_days: 30,
        };
        let logger = AuditLogger::new(config);

        let event = AuditEvent {
            timestamp: Utc::now(),
            event_type: EventType::ModelRequest,
            provider: "test".to_string(),
            model: "test-model".to_string(),
            request_id: "test-123".to_string(),
            user_id: None,
            success: true,
            error: None,
            metadata: HashMap::new(),
        };

        logger.log_event(event.clone()).await.unwrap();

        let events = logger.get_events(None).await;
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].request_id, "test-123");
    }

    #[tokio::test]
    async fn test_event_filtering() {
        let config = AuditConfig {
            log_file: None,
            log_level: LogLevel::Basic,
            retention_days: 30,
        };
        let logger = AuditLogger::new(config);

        // Add some test events
        let success_event = AuditEvent {
            timestamp: Utc::now(),
            event_type: EventType::ModelRequest,
            provider: "test".to_string(),
            model: "test-model".to_string(),
            request_id: "success-123".to_string(),
            user_id: None,
            success: true,
            error: None,
            metadata: HashMap::new(),
        };

        let error_event = AuditEvent {
            timestamp: Utc::now(),
            event_type: EventType::Error,
            provider: "test".to_string(),
            model: "test-model".to_string(),
            request_id: "error-123".to_string(),
            user_id: None,
            success: false,
            error: Some("test error".to_string()),
            metadata: HashMap::new(),
        };

        logger.log_event(success_event).await.unwrap();
        logger.log_event(error_event).await.unwrap();

        // Test success_only filter
        let filter = EventFilter {
            start_time: None,
            end_time: None,
            event_types: None,
            provider: None,
            success_only: true,
        };

        let filtered_events = logger.get_events(Some(filter)).await;
        assert_eq!(filtered_events.len(), 1);
        assert!(filtered_events[0].success);
    }

    #[tokio::test]
    async fn test_event_cleanup() {
        let config = AuditConfig {
            log_file: None,
            log_level: LogLevel::Basic,
            retention_days: 30,
        };
        let logger = AuditLogger::new(config);

        // Add old and new events
        let old_event = AuditEvent {
            timestamp: Utc::now() - chrono::Duration::days(31),
            event_type: EventType::ModelRequest,
            provider: "test".to_string(),
            model: "test-model".to_string(),
            request_id: "old-123".to_string(),
            user_id: None,
            success: true,
            error: None,
            metadata: HashMap::new(),
        };

        let new_event = AuditEvent {
            timestamp: Utc::now(),
            event_type: EventType::ModelRequest,
            provider: "test".to_string(),
            model: "test-model".to_string(),
            request_id: "new-123".to_string(),
            user_id: None,
            success: true,
            error: None,
            metadata: HashMap::new(),
        };

        logger.log_event(old_event).await.unwrap();
        logger.log_event(new_event).await.unwrap();

        logger.cleanup_old_events().await.unwrap();

        let events = logger.get_events(None).await;
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].request_id, "new-123");
    }
}