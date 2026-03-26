use crate::provider::{ModelRequest, ModelResponse};
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, sync::Arc, time::Instant};
use tokio::sync::RwLock;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    pub max_request_size: usize,
    pub rate_limit_requests: u32,
    pub rate_limit_window: u32,
    pub blocked_patterns: Vec<String>,
    pub sanitization_rules: Vec<SanitizationRule>,
    pub threat_detection: ThreatDetectionConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SanitizationRule {
    pub pattern: String,
    pub replacement: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatDetectionConfig {
    pub anomaly_threshold: f64,
    pub max_request_frequency: u32,
    pub suspicious_patterns: Vec<String>,
    pub ip_blacklist: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct SecurityEvent {
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub event_type: SecurityEventType,
    pub severity: SecuritySeverity,
    pub details: HashMap<String, String>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum SecurityEventType {
    RateLimitExceeded,
    BlockedPattern,
    AnomalyDetected,
    SuspiciousActivity,
    AuthenticationFailure,
}

#[derive(Debug, Clone, PartialEq)]
pub enum SecuritySeverity {
    Low,
    Medium,
    High,
    Critical,
}

pub struct SecurityManager {
    config: SecurityConfig,
    rate_limiter: Arc<RwLock<HashMap<String, Vec<Instant>>>>,
    events: Arc<RwLock<Vec<SecurityEvent>>>,
    anomaly_detector: AnomalyDetector,
}

impl SecurityManager {
    pub fn new(config: SecurityConfig) -> Self {
        Self {
            config: config.clone(),
            rate_limiter: Arc::new(RwLock::new(HashMap::new())),
            events: Arc::new(RwLock::new(Vec::new())),
            anomaly_detector: AnomalyDetector::new(config.threat_detection),
        }
    }

    pub async fn validate_request(&self, request: &ModelRequest, client_id: &str) -> Result<()> {
        // Check request size
        let request_size = request
            .messages
            .iter()
            .map(|m| m.content.len())
            .sum::<usize>();
        if request_size > self.config.max_request_size {
            self.log_security_event(
                SecurityEventType::SuspiciousActivity,
                SecuritySeverity::Medium,
                HashMap::from([
                    ("client_id".to_string(), client_id.to_string()),
                    ("request_size".to_string(), request_size.to_string()),
                    ("max_size".to_string(), self.config.max_request_size.to_string()),
                ]),
            )
            .await;
            anyhow::bail!("Request size exceeds maximum allowed");
        }

        // Check rate limiting
        if !self.check_rate_limit(client_id).await? {
            self.log_security_event(
                SecurityEventType::RateLimitExceeded,
                SecuritySeverity::Medium,
                HashMap::from([("client_id".to_string(), client_id.to_string())]),
            )
            .await;
            anyhow::bail!("Rate limit exceeded");
        }

        // Check blocked patterns
        for pattern in &self.config.blocked_patterns {
            let regex = regex::Regex::new(pattern)?;
            for message in &request.messages {
                if regex.is_match(&message.content) {
                    self.log_security_event(
                        SecurityEventType::BlockedPattern,
                        SecuritySeverity::High,
                        HashMap::from([
                            ("client_id".to_string(), client_id.to_string()),
                            ("pattern".to_string(), pattern.clone()),
                        ]),
                    )
                    .await;
                    anyhow::bail!("Request contains blocked pattern");
                }
            }
        }

        Ok(())
    }

    pub async fn sanitize_request(&self, request: &mut ModelRequest) -> Result<()> {
        for rule in &self.config.sanitization_rules {
            let regex = regex::Regex::new(&rule.pattern)?;
            for message in &mut request.messages {
                message.content = regex.replace_all(&message.content, &rule.replacement).to_string();
            }
        }
        Ok(())
    }

    pub async fn validate_response(
        &self,
        response: &ModelResponse,
        client_id: &str,
    ) -> Result<()> {
        // Check for anomalies in response
        if self.anomaly_detector.detect_anomalies(response).await? {
            self.log_security_event(
                SecurityEventType::AnomalyDetected,
                SecuritySeverity::High,
                HashMap::from([("client_id".to_string(), client_id.to_string())]),
            )
            .await;
            anyhow::bail!("Response contains anomalies");
        }

        Ok(())
    }

    async fn check_rate_limit(&self, client_id: &str) -> Result<bool> {
        let now = Instant::now();
        let window_start = now - std::time::Duration::from_secs(self.config.rate_limit_window as u64);

        let mut rate_limiter = self.rate_limiter.write().await;
        let requests = rate_limiter.entry(client_id.to_string()).or_insert_with(Vec::new);

        // Remove old requests
        requests.retain(|&time| time > window_start);

        // Check if limit exceeded
        if requests.len() >= self.config.rate_limit_requests as usize {
            return Ok(false);
        }

        // Add new request
        requests.push(now);
        Ok(true)
    }

    pub async fn log_security_event(
        &self,
        event_type: SecurityEventType,
        severity: SecuritySeverity,
        details: HashMap<String, String>,
    ) {
        let event = SecurityEvent {
            timestamp: chrono::Utc::now(),
            event_type,
            severity,
            details,
        };

        let mut events = self.events.write().await;
        events.push(event);

        // Implement real-time alerting for high-severity events
        if severity == SecuritySeverity::High || severity == SecuritySeverity::Critical {
            self.trigger_alert(&events.last().unwrap()).await;
        }
    }

    async fn trigger_alert(&self, event: &SecurityEvent) {
        // In a real implementation, this would send alerts to monitoring systems
        tracing::warn!(
            "Security alert: {:?} - Severity: {:?} - Details: {:?}",
            event.event_type,
            event.severity,
            event.details
        );
    }

    pub async fn get_security_events(&self) -> Vec<SecurityEvent> {
        self.events.read().await.clone()
    }
}

struct AnomalyDetector {
    config: ThreatDetectionConfig,
    recent_patterns: Arc<RwLock<Vec<String>>>,
}

impl AnomalyDetector {
    fn new(config: ThreatDetectionConfig) -> Self {
        Self {
            config,
            recent_patterns: Arc::new(RwLock::new(Vec::new())),
        }
    }

    async fn detect_anomalies(&self, response: &ModelResponse) -> Result<bool> {
        // Check for suspicious patterns
        for pattern in &self.config.suspicious_patterns {
            let regex = regex::Regex::new(pattern)?;
            if regex.is_match(&response.content) {
                return Ok(true);
            }
        }

        // Detect unusual patterns or behavior
        let mut patterns = self.recent_patterns.write().await;
        patterns.push(response.content.clone());
        if patterns.len() > 100 {
            patterns.remove(0);
        }

        // Simple frequency analysis
        let mut frequency = HashMap::new();
        for pattern in patterns.iter() {
            *frequency.entry(pattern).or_insert(0) += 1;
        }

        for (pattern, count) in frequency {
            let frequency = count as f64 / patterns.len() as f64;
            if frequency > self.config.anomaly_threshold {
                return Ok(true);
            }
        }

        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provider::Message;

    fn create_test_config() -> SecurityConfig {
        SecurityConfig {
            max_request_size: 1000,
            rate_limit_requests: 10,
            rate_limit_window: 60,
            blocked_patterns: vec![r"(?i)password:\s*\w+".to_string()],
            sanitization_rules: vec![SanitizationRule {
                pattern: r"(?i)(api[_-]?key|secret|token)\s*[:=]\s*\w+".to_string(),
                replacement: "[REDACTED]".to_string(),
            }],
            threat_detection: ThreatDetectionConfig {
                anomaly_threshold: 0.8,
                max_request_frequency: 100,
                suspicious_patterns: vec![r"(?i)eval\(.+\)".to_string()],
                ip_blacklist: vec!["127.0.0.1".to_string()],
            },
        }
    }

    #[tokio::test]
    async fn test_request_validation() {
        let manager = SecurityManager::new(create_test_config());

        // Test oversized request
        let large_request = ModelRequest {
            model: "test".to_string(),
            messages: vec![Message {
                role: "user".to_string(),
                content: "a".repeat(2000),
            }],
            temperature: None,
            max_tokens: None,
            stream: None,
        };

        assert!(manager
            .validate_request(&large_request, "test-client")
            .await
            .is_err());

        // Test blocked pattern
        let blocked_request = ModelRequest {
            model: "test".to_string(),
            messages: vec![Message {
                role: "user".to_string(),
                content: "password: secret123".to_string(),
            }],
            temperature: None,
            max_tokens: None,
            stream: None,
        };

        assert!(manager
            .validate_request(&blocked_request, "test-client")
            .await
            .is_err());
    }

    #[tokio::test]
    async fn test_rate_limiting() {
        let manager = SecurityManager::new(create_test_config());
        let client_id = "test-client";

        // Make requests up to limit
        for _ in 0..10 {
            assert!(manager.check_rate_limit(client_id).await.unwrap());
        }

        // Next request should be rate limited
        assert!(!manager.check_rate_limit(client_id).await.unwrap());
    }

    #[tokio::test]
    async fn test_response_validation() {
        let manager = SecurityManager::new(create_test_config());

        // Test suspicious pattern
        let response = ModelResponse {
            content: "eval(malicious_code())".to_string(),
            model: "test".to_string(),
            usage: None,
        };

        assert!(manager
            .validate_response(&response, "test-client")
            .await
            .is_err());
    }

    #[tokio::test]
    async fn test_request_sanitization() {
        let manager = SecurityManager::new(create_test_config());

        let mut request = ModelRequest {
            model: "test".to_string(),
            messages: vec![Message {
                role: "user".to_string(),
                content: "api_key=secret123 token=abc123".to_string(),
            }],
            temperature: None,
            max_tokens: None,
            stream: None,
        };

        manager.sanitize_request(&mut request).await.unwrap();
        assert!(request.messages[0].content.contains("[REDACTED]"));
        assert!(!request.messages[0].content.contains("secret123"));
    }

    #[tokio::test]
    async fn test_security_event_logging() {
        let manager = SecurityManager::new(create_test_config());

        let details = HashMap::from([("test_key".to_string(), "test_value".to_string())]);
        manager
            .log_security_event(
                SecurityEventType::SuspiciousActivity,
                SecuritySeverity::High,
                details,
            )
            .await;

        let events = manager.get_security_events().await;
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type, SecurityEventType::SuspiciousActivity);
        assert_eq!(events[0].severity, SecuritySeverity::High);
    }
}