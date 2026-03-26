use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::RwLock;
use anyhow::Result;

#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    pub requests_per_minute: u32,
    pub burst_limit: u32,
    pub quota_per_day: Option<u32>,
}

#[derive(Debug)]
struct RateLimitState {
    last_reset: Instant,
    current_count: u32,
    daily_count: u32,
    last_daily_reset: Instant,
}

impl RateLimitState {
    fn new() -> Self {
        Self {
            last_reset: Instant::now(),
            current_count: 0,
            daily_count: 0,
            last_daily_reset: Instant::now(),
        }
    }
}

pub struct RateLimiter {
    config: RateLimitConfig,
    state: Arc<RwLock<HashMap<String, RateLimitState>>>,
}

impl RateLimiter {
    pub fn new(config: RateLimitConfig) -> Self {
        Self {
            config,
            state: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn check_rate_limit(&self, key: &str) -> Result<bool> {
        let mut state = self.state.write().await;
        let now = Instant::now();

        let entry = state.entry(key.to_string()).or_insert_with(RateLimitState::new);

        // Check and reset daily quota
        if now.duration_since(entry.last_daily_reset) >= Duration::from_secs(86400) {
            entry.daily_count = 0;
            entry.last_daily_reset = now;
        }

        // Check daily quota if configured
        if let Some(daily_quota) = self.config.quota_per_day {
            if entry.daily_count >= daily_quota {
                return Ok(false);
            }
        }

        // Check and reset per-minute counter
        if now.duration_since(entry.last_reset) >= Duration::from_secs(60) {
            entry.current_count = 0;
            entry.last_reset = now;
        }

        // Check rate limit
        if entry.current_count >= self.config.requests_per_minute {
            // Allow burst up to burst_limit
            if entry.current_count < self.config.burst_limit {
                entry.current_count += 1;
                entry.daily_count += 1;
                return Ok(true);
            }
            return Ok(false);
        }

        // Increment counters
        entry.current_count += 1;
        entry.daily_count += 1;

        Ok(true)
    }

    pub async fn get_remaining_quota(&self, key: &str) -> Result<Option<u32>> {
        let state = self.state.read().await;

        if let Some(daily_quota) = self.config.quota_per_day {
            if let Some(entry) = state.get(key) {
                let remaining = daily_quota.saturating_sub(entry.daily_count);
                Ok(Some(remaining))
            } else {
                Ok(Some(daily_quota))
            }
        } else {
            Ok(None)
        }
    }

    pub async fn cleanup_old_entries(&self) {
        let mut state = self.state.write().await;
        let now = Instant::now();

        // Remove entries that haven't been used in 24 hours
        state.retain(|_, entry| {
            now.duration_since(entry.last_reset) < Duration::from_secs(86400)
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::{sleep, Duration};

    #[tokio::test]
    async fn test_basic_rate_limiting() {
        let config = RateLimitConfig {
            requests_per_minute: 2,
            burst_limit: 3,
            quota_per_day: None,
        };
        let limiter = RateLimiter::new(config);

        assert!(limiter.check_rate_limit("test").await.unwrap()); // 1
        assert!(limiter.check_rate_limit("test").await.unwrap()); // 2
        assert!(limiter.check_rate_limit("test").await.unwrap()); // 3 (burst)
        assert!(!limiter.check_rate_limit("test").await.unwrap()); // Should be blocked
    }

    #[tokio::test]
    async fn test_quota_limiting() {
        let config = RateLimitConfig {
            requests_per_minute: 10,
            burst_limit: 15,
            quota_per_day: Some(3),
        };
        let limiter = RateLimiter::new(config);

        assert!(limiter.check_rate_limit("test").await.unwrap()); // 1
        assert!(limiter.check_rate_limit("test").await.unwrap()); // 2
        assert!(limiter.check_rate_limit("test").await.unwrap()); // 3
        assert!(!limiter.check_rate_limit("test").await.unwrap()); // Should be blocked by quota
    }

    #[tokio::test]
    async fn test_rate_limit_reset() {
        let config = RateLimitConfig {
            requests_per_minute: 1,
            burst_limit: 2,
            quota_per_day: None,
        };
        let limiter = RateLimiter::new(config);

        assert!(limiter.check_rate_limit("test").await.unwrap());
        assert!(limiter.check_rate_limit("test").await.unwrap()); // burst
        assert!(!limiter.check_rate_limit("test").await.unwrap());

        // Wait for reset
        sleep(Duration::from_secs(60)).await;

        assert!(limiter.check_rate_limit("test").await.unwrap());
    }

    #[tokio::test]
    async fn test_multiple_keys() {
        let config = RateLimitConfig {
            requests_per_minute: 1,
            burst_limit: 2,
            quota_per_day: None,
        };
        let limiter = RateLimiter::new(config);

        assert!(limiter.check_rate_limit("test1").await.unwrap());
        assert!(limiter.check_rate_limit("test2").await.unwrap());
        assert!(limiter.check_rate_limit("test1").await.unwrap()); // burst
        assert!(limiter.check_rate_limit("test2").await.unwrap()); // burst
        assert!(!limiter.check_rate_limit("test1").await.unwrap());
        assert!(!limiter.check_rate_limit("test2").await.unwrap());
    }
}