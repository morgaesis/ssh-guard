use crate::provider::{ModelRequest, ModelResponse};
use anyhow::Result;
use futures::Stream;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    pin::Pin,
    sync::Arc,
    time::{Duration, SystemTime},
};
use tokio::sync::RwLock;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheConfig {
    pub max_size: usize,
    pub ttl: Duration,
    pub dedup_window: Duration,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            max_size: 1000,
            ttl: Duration::from_secs(3600), // 1 hour
            dedup_window: Duration::from_secs(5), // 5 seconds
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CacheEntry {
    response: ModelResponse,
    timestamp: SystemTime,
}

#[derive(Debug, Clone)]
struct InFlightRequest {
    timestamp: SystemTime,
    response_tx: Vec<tokio::sync::oneshot::Sender<Result<ModelResponse>>>,
}

pub struct Cache {
    config: CacheConfig,
    cache: Arc<RwLock<HashMap<String, CacheEntry>>>,
    in_flight: Arc<RwLock<HashMap<String, InFlightRequest>>>,
}

impl Cache {
    pub fn new(config: CacheConfig) -> Self {
        Self {
            config,
            cache: Arc::new(RwLock::new(HashMap::new())),
            in_flight: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn get(&self, key: &str) -> Option<ModelResponse> {
        let cache = self.cache.read().await;
        if let Some(entry) = cache.get(key) {
            if entry.timestamp.elapsed().unwrap() < self.config.ttl {
                return Some(entry.response.clone());
            }
        }
        None
    }

    pub async fn set(&self, key: String, response: ModelResponse) {
        let mut cache = self.cache.write().await;

        // Enforce cache size limit with LRU eviction
        if cache.len() >= self.config.max_size {
            let oldest = cache
                .iter()
                .min_by_key(|(_, entry)| entry.timestamp)
                .map(|(k, _)| k.clone());

            if let Some(oldest_key) = oldest {
                cache.remove(&oldest_key);
            }
        }

        cache.insert(
            key,
            CacheEntry {
                response,
                timestamp: SystemTime::now(),
            },
        );
    }

    pub async fn register_in_flight(
        &self,
        key: String,
        tx: tokio::sync::oneshot::Sender<Result<ModelResponse>>,
    ) -> bool {
        let mut in_flight = self.in_flight.write().await;

        match in_flight.get_mut(&key) {
            Some(req) => {
                // Request is already in flight
                if req.timestamp.elapsed().unwrap() < self.config.dedup_window {
                    req.response_tx.push(tx);
                    true
                } else {
                    // Request is too old, remove it
                    in_flight.remove(&key);
                    false
                }
            }
            None => {
                // New in-flight request
                in_flight.insert(
                    key,
                    InFlightRequest {
                        timestamp: SystemTime::now(),
                        response_tx: vec![tx],
                    },
                );
                false
            }
        }
    }

    pub async fn complete_in_flight(&self, key: &str, result: Result<ModelResponse>) {
        let mut in_flight = self.in_flight.write().await;
        if let Some(req) = in_flight.remove(key) {
            for tx in req.response_tx {
                let _ = tx.send(result.clone());
            }
        }
    }

    pub async fn cleanup(&self) {
        let mut cache = self.cache.write().await;
        cache.retain(|_, entry| entry.timestamp.elapsed().unwrap() < self.config.ttl);

        let mut in_flight = self.in_flight.write().await;
        in_flight.retain(|_, req| req.timestamp.elapsed().unwrap() < self.config.dedup_window);
    }
}

#[derive(Clone)]
pub struct CacheMiddleware {
    cache: Arc<Cache>,
}

impl CacheMiddleware {
    pub fn new(config: CacheConfig) -> Self {
        Self {
            cache: Arc::new(Cache::new(config)),
        }
    }

    pub async fn process_request<F, Fut>(
        &self,
        request: &ModelRequest,
        process_fn: F,
    ) -> Result<ModelResponse>
    where
        F: FnOnce(ModelRequest) -> Fut,
        Fut: std::future::Future<Output = Result<ModelResponse>>,
    {
        // Don't cache streaming requests
        if request.stream.unwrap_or(false) {
            return process_fn(request.clone()).await;
        }

        let cache_key = self.generate_cache_key(request);

        // Check cache first
        if let Some(cached) = self.cache.get(&cache_key).await {
            return Ok(cached);
        }

        // Set up deduplication channel
        let (tx, rx) = tokio::sync::oneshot::channel();

        // Check if request is already in flight
        if self.cache.register_in_flight(cache_key.clone(), tx).await {
            return rx.await?;
        }

        // Process request
        let result = process_fn(request.clone()).await;

        // Cache successful responses
        if let Ok(ref response) = result {
            self.cache.set(cache_key.clone(), response.clone()).await;
        }

        // Complete in-flight request
        self.cache.complete_in_flight(&cache_key, result.clone()).await;

        result
    }

    fn generate_cache_key(&self, request: &ModelRequest) -> String {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();

        // Include model and messages in cache key
        hasher.update(request.model.as_bytes());
        for msg in &request.messages {
            hasher.update(msg.role.as_bytes());
            hasher.update(msg.content.as_bytes());
        }

        // Include temperature if set (rounded to 2 decimal places)
        if let Some(temp) = request.temperature {
            hasher.update(format!("{:.2}", temp).as_bytes());
        }

        format!("{:x}", hasher.finalize())
    }

    pub async fn cleanup_task(self) {
        loop {
            tokio::time::sleep(Duration::from_secs(60)).await;
            self.cache.cleanup().await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::sleep;

    #[tokio::test]
    async fn test_cache_basic() {
        let config = CacheConfig {
            max_size: 10,
            ttl: Duration::from_secs(1),
            dedup_window: Duration::from_secs(1),
        };
        let middleware = CacheMiddleware::new(config);

        let request = ModelRequest {
            model: "test".to_string(),
            messages: vec![],
            temperature: Some(0.7),
            max_tokens: Some(100),
            stream: None,
        };

        let response = ModelResponse {
            content: "test response".to_string(),
            model: "test".to_string(),
            usage: None,
        };

        // First request should process
        let result = middleware
            .process_request(&request, |_| async {
                sleep(Duration::from_millis(100)).await;
                Ok(response.clone())
            })
            .await;
        assert!(result.is_ok());

        // Second request should hit cache
        let cached = middleware
            .process_request(&request, |_| async {
                panic!("Should not be called");
                #[allow(unreachable_code)]
                Ok(response.clone())
            })
            .await;
        assert!(cached.is_ok());
        assert_eq!(cached.unwrap().content, "test response");

        // Wait for cache to expire
        sleep(Duration::from_secs(2)).await;

        // Third request should process again
        let result = middleware
            .process_request(&request, |_| async {
                Ok(response.clone())
            })
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_request_deduplication() {
        let config = CacheConfig {
            max_size: 10,
            ttl: Duration::from_secs(10),
            dedup_window: Duration::from_secs(1),
        };
        let middleware = CacheMiddleware::new(config.clone());

        let request = ModelRequest {
            model: "test".to_string(),
            messages: vec![],
            temperature: Some(0.7),
            max_tokens: Some(100),
            stream: None,
        };

        let response = ModelResponse {
            content: "test response".to_string(),
            model: "test".to_string(),
            usage: None,
        };

        // Launch multiple concurrent requests
        let middleware_clone = middleware.clone();
        let request_clone = request.clone();
        let response_clone = response.clone();

        let handle1 = tokio::spawn(async move {
            middleware_clone
                .process_request(&request_clone, |_| async {
                    sleep(Duration::from_millis(100)).await;
                    Ok(response_clone)
                })
                .await
        });

        let handle2 = tokio::spawn(async move {
            middleware
                .process_request(&request, |_| async {
                    panic!("Second request should be deduplicated");
                    #[allow(unreachable_code)]
                    Ok(response)
                })
                .await
        });

        let (result1, result2) = tokio::join!(handle1, handle2);
        assert!(result1.unwrap().is_ok());
        assert!(result2.unwrap().is_ok());
    }

    #[tokio::test]
    async fn test_streaming_bypass() {
        let config = CacheConfig::default();
        let middleware = CacheMiddleware::new(config);

        let mut request = ModelRequest {
            model: "test".to_string(),
            messages: vec![],
            temperature: Some(0.7),
            max_tokens: Some(100),
            stream: Some(true),
        };

        let response = ModelResponse {
            content: "test response".to_string(),
            model: "test".to_string(),
            usage: None,
        };

        // First streaming request should process
        let result1 = middleware
            .process_request(&request, |_| async {
                sleep(Duration::from_millis(100)).await;
                Ok(response.clone())
            })
            .await;

        // Second streaming request should also process
        request.messages = vec![]; // Clear messages to ensure same cache key
        let result2 = middleware
            .process_request(&request, |_| async {
                sleep(Duration::from_millis(100)).await;
                Ok(response.clone())
            })
            .await;

        assert!(result1.is_ok());
        assert!(result2.is_ok());
    }
}