use crate::provider::{ModelProvider, ModelRequest, ModelResponse};
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, sync::Arc};
use tokio::sync::RwLock;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelConfig {
    pub name: String,
    pub provider: String,
    pub cost_per_token: f64,
    pub max_tokens: u32,
    pub capabilities: Vec<String>,
    pub performance_score: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OptimizationConfig {
    pub models: Vec<ModelConfig>,
    pub fallback_chain: Vec<String>,
    pub cost_threshold: f64,
    pub performance_threshold: f32,
}

#[derive(Debug, Clone)]
pub struct UsageStats {
    pub total_tokens: u64,
    pub total_cost: f64,
    pub requests: u64,
    pub errors: u64,
    pub average_latency: f64,
}

pub struct CostOptimizer {
    config: OptimizationConfig,
    usage_stats: Arc<RwLock<HashMap<String, UsageStats>>>,
    model_selection_cache: Arc<RwLock<HashMap<String, String>>>,
}

impl CostOptimizer {
    pub fn new(config: OptimizationConfig) -> Self {
        Self {
            config,
            usage_stats: Arc::new(RwLock::new(HashMap::new())),
            model_selection_cache: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn select_model(&self, request: &ModelRequest) -> Result<String> {
        // Check cache first
        let cache_key = self.generate_cache_key(request);
        if let Some(model) = self.model_selection_cache.read().await.get(&cache_key) {
            return Ok(model.clone());
        }

        // Analyze request complexity
        let complexity = self.analyze_complexity(request).await;

        // Find suitable models based on capabilities and complexity
        let suitable_models: Vec<&ModelConfig> = self
            .config
            .models
            .iter()
            .filter(|m| self.model_meets_requirements(m, request, complexity))
            .collect();

        // Sort by cost and performance
        let mut ranked_models = suitable_models;
        ranked_models.sort_by(|a, b| {
            let a_score = self.calculate_model_score(a, complexity);
            let b_score = self.calculate_model_score(b, complexity);
            b_score.partial_cmp(&a_score).unwrap()
        });

        // Select best model
        if let Some(model) = ranked_models.first() {
            let mut cache = self.model_selection_cache.write().await;
            cache.insert(cache_key, model.name.clone());
            Ok(model.name.clone())
        } else {
            // Fall back to default model in fallback chain
            Ok(self.config.fallback_chain[0].clone())
        }
    }

    async fn analyze_complexity(&self, request: &ModelRequest) -> f32 {
        let mut complexity = 0.0;

        // Token count
        let total_tokens: usize = request
            .messages
            .iter()
            .map(|m| m.content.split_whitespace().count())
            .sum();
        complexity += (total_tokens as f32) / 100.0;

        // Message context length
        complexity += (request.messages.len() as f32) / 5.0;

        // Code detection
        if request.messages.iter().any(|m| m.content.contains("```")) {
            complexity += 1.0;
        }

        complexity.min(1.0)
    }

    fn model_meets_requirements(
        &self,
        model: &ModelConfig,
        request: &ModelRequest,
        complexity: f32,
    ) -> bool {
        // Check token limit
        let estimated_tokens = request
            .messages
            .iter()
            .map(|m| m.content.split_whitespace().count())
            .sum::<usize>();
        if estimated_tokens > model.max_tokens as usize {
            return false;
        }

        // Check capabilities
        if request.messages.iter().any(|m| m.content.contains("```"))
            && !model.capabilities.contains(&"code".to_string())
        {
            return false;
        }

        // Check performance requirements
        if complexity > 0.7 && model.performance_score < 0.8 {
            return false;
        }

        true
    }

    fn calculate_model_score(&self, model: &ModelConfig, complexity: f32) -> f32 {
        let cost_score = 1.0 - (model.cost_per_token as f32 / 0.01); // Normalize to 0-1
        let performance_score = model.performance_score;
        let complexity_match = 1.0 - (complexity - model.performance_score).abs();

        // Weighted scoring
        0.4 * cost_score + 0.4 * performance_score + 0.2 * complexity_match
    }

    fn generate_cache_key(&self, request: &ModelRequest) -> String {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();

        // Hash relevant request properties
        for msg in &request.messages {
            hasher.update(msg.content.as_bytes());
        }

        format!("{:x}", hasher.finalize())
    }

    pub async fn record_usage(
        &self,
        model: &str,
        tokens: u64,
        cost: f64,
        latency: f64,
        is_error: bool,
    ) {
        let mut stats = self.usage_stats.write().await;
        let entry = stats.entry(model.to_string()).or_insert(UsageStats {
            total_tokens: 0,
            total_cost: 0.0,
            requests: 0,
            errors: 0,
            average_latency: 0.0,
        });

        entry.total_tokens += tokens;
        entry.total_cost += cost;
        entry.requests += 1;
        if is_error {
            entry.errors += 1;
        }

        // Update running average latency
        entry.average_latency = (entry.average_latency * (entry.requests - 1) as f64 + latency)
            / entry.requests as f64;
    }

    pub async fn get_usage_report(&self) -> HashMap<String, UsageStats> {
        self.usage_stats.read().await.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_config() -> OptimizationConfig {
        OptimizationConfig {
            models: vec![
                ModelConfig {
                    name: "gpt-4".to_string(),
                    provider: "openai".to_string(),
                    cost_per_token: 0.01,
                    max_tokens: 8000,
                    capabilities: vec!["code".to_string(), "math".to_string()],
                    performance_score: 0.95,
                },
                ModelConfig {
                    name: "gpt-3.5-turbo".to_string(),
                    provider: "openai".to_string(),
                    cost_per_token: 0.002,
                    max_tokens: 4000,
                    capabilities: vec!["code".to_string()],
                    performance_score: 0.8,
                },
            ],
            fallback_chain: vec!["gpt-3.5-turbo".to_string()],
            cost_threshold: 0.05,
            performance_threshold: 0.8,
        }
    }

    #[tokio::test]
    async fn test_model_selection() {
        let optimizer = CostOptimizer::new(create_test_config());

        // Simple request should use cheaper model
        let simple_request = ModelRequest {
            model: "auto".to_string(),
            messages: vec![crate::provider::Message {
                role: "user".to_string(),
                content: "Hello, how are you?".to_string(),
            }],
            temperature: None,
            max_tokens: None,
            stream: None,
        };

        let model = optimizer.select_model(&simple_request).await.unwrap();
        assert_eq!(model, "gpt-3.5-turbo");

        // Complex code request should use more capable model
        let complex_request = ModelRequest {
            model: "auto".to_string(),
            messages: vec![crate::provider::Message {
                role: "user".to_string(),
                content: "```python\ndef complex_function():\n    pass```".to_string(),
            }],
            temperature: None,
            max_tokens: None,
            stream: None,
        };

        let model = optimizer.select_model(&complex_request).await.unwrap();
        assert_eq!(model, "gpt-4");
    }

    #[tokio::test]
    async fn test_usage_tracking() {
        let optimizer = CostOptimizer::new(create_test_config());

        optimizer
            .record_usage("gpt-4", 100, 0.01, 0.5, false)
            .await;
        optimizer
            .record_usage("gpt-4", 200, 0.02, 1.0, false)
            .await;

        let stats = optimizer.get_usage_report().await;
        let gpt4_stats = stats.get("gpt-4").unwrap();

        assert_eq!(gpt4_stats.total_tokens, 300);
        assert_eq!(gpt4_stats.total_cost, 0.03);
        assert_eq!(gpt4_stats.requests, 2);
        assert_eq!(gpt4_stats.errors, 0);
        assert!((gpt4_stats.average_latency - 0.75).abs() < 0.001);
    }

    #[tokio::test]
    async fn test_model_selection_caching() {
        let optimizer = CostOptimizer::new(create_test_config());

        let request = ModelRequest {
            model: "auto".to_string(),
            messages: vec![crate::provider::Message {
                role: "user".to_string(),
                content: "Test message".to_string(),
            }],
            temperature: None,
            max_tokens: None,
            stream: None,
        };

        // First call should compute model
        let model1 = optimizer.select_model(&request).await.unwrap();

        // Second call should use cache
        let model2 = optimizer.select_model(&request).await.unwrap();

        assert_eq!(model1, model2);
    }
}