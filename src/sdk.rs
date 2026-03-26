use crate::{
    cache::CacheMiddleware,
    config::Config,
    metrics::MetricsCollector,
    optimizer::CostOptimizer,
    provider::{ModelProvider, ModelRequest, ModelResponse, ProviderRegistry},
    validator::ResponseValidator,
};
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientConfig {
    pub providers: Vec<ProviderConfig>,
    pub cache_enabled: bool,
    pub validation_enabled: bool,
    pub optimization_enabled: bool,
    pub metrics_enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderConfig {
    pub name: String,
    pub api_key: String,
    pub endpoint: Option<String>,
}

/// Client for interacting with the model guard system.
///
/// The ModelGuardClient provides a high-level interface for making requests
/// to language models with built-in security, validation, and optimization.
///
/// # Examples
///
/// ```rust
/// use ssh_guard::sdk::{ModelGuardClient, ClientConfig, ProviderConfig};
///
/// #[tokio::main]
/// async fn main() -> Result<()> {
///     let config = ClientConfig {
///         providers: vec![
///             ProviderConfig {
///                 name: "openai".to_string(),
///                 api_key: "your-api-key".to_string(),
///                 endpoint: None,
///             }
///         ],
///         cache_enabled: true,
///         validation_enabled: true,
///         optimization_enabled: true,
///         metrics_enabled: true,
///     };
///
///     let client = ModelGuardClient::new(config).await?;
///
///     let response = client
///         .send_message("Tell me a joke", "gpt-4")
///         .await?;
///
///     println!("Response: {}", response.content);
///     Ok(())
/// }
/// ```
pub struct ModelGuardClient {
    registry: Arc<ProviderRegistry>,
    cache: Option<Arc<CacheMiddleware>>,
    validator: Option<Arc<ResponseValidator>>,
    optimizer: Option<Arc<CostOptimizer>>,
    metrics: Option<Arc<MetricsCollector>>,
}

impl ModelGuardClient {
    /// Create a new ModelGuardClient with the specified configuration.
    pub async fn new(config: ClientConfig) -> Result<Self> {
        let mut registry = ProviderRegistry::new();

        // Initialize providers
        for provider_config in &config.providers {
            let provider: Box<dyn ModelProvider> = match provider_config.name.as_str() {
                "openai" => Box::new(crate::providers::openai::OpenAIProvider::new(
                    provider_config.api_key.clone(),
                )),
                "anthropic" => Box::new(crate::providers::claude::ClaudeProvider::new(
                    provider_config.api_key.clone(),
                )),
                _ => anyhow::bail!("Unsupported provider: {}", provider_config.name),
            };
            registry.register(provider_config.name.clone(), provider);
        }

        let registry = Arc::new(registry);

        // Initialize optional components
        let cache = if config.cache_enabled {
            Some(Arc::new(CacheMiddleware::new(Default::default())))
        } else {
            None
        };

        let validator = if config.validation_enabled {
            Some(Arc::new(ResponseValidator::new()))
        } else {
            None
        };

        let optimizer = if config.optimization_enabled {
            Some(Arc::new(CostOptimizer::new(Default::default())))
        } else {
            None
        };

        let metrics = if config.metrics_enabled {
            Some(Arc::new(MetricsCollector::new()?))
        } else {
            None
        };

        Ok(Self {
            registry,
            cache,
            validator,
            optimizer,
            metrics,
        })
    }

    /// Send a message to a specific model.
    ///
    /// # Arguments
    ///
    /// * `content` - The message content to send
    /// * `model` - The model to use (e.g., "gpt-4", "claude-3-opus")
    ///
    /// # Returns
    ///
    /// The model's response, after passing through validation and processing.
    pub async fn send_message(&self, content: &str, model: &str) -> Result<ModelResponse> {
        let request = ModelRequest {
            model: model.to_string(),
            messages: vec![crate::provider::Message {
                role: "user".to_string(),
                content: content.to_string(),
            }],
            temperature: None,
            max_tokens: None,
            stream: None,
        };

        self.process_request(request).await
    }

    /// Process a full model request with custom parameters.
    ///
    /// # Arguments
    ///
    /// * `request` - The complete ModelRequest with all parameters
    ///
    /// # Returns
    ///
    /// The model's response, after passing through validation and processing.
    pub async fn process_request(&self, mut request: ModelRequest) -> Result<ModelResponse> {
        let start_time = std::time::Instant::now();

        // Optimize model selection if enabled
        if let Some(optimizer) = &self.optimizer {
            if request.model == "auto" {
                request.model = optimizer.select_model(&request).await?;
            }
        }

        // Get provider for the model
        let provider = self
            .registry
            .get(&request.model)
            .ok_or_else(|| anyhow::anyhow!("No provider found for model: {}", request.model))?;

        // Try cache first if enabled
        if let Some(cache) = &self.cache {
            if let Some(cached_response) = cache
                .process_request(&request, |r| provider.process_request(r))
                .await?
            {
                return Ok(cached_response);
            }
        }

        // Process request
        let response = provider.process_request(request.clone()).await?;

        // Validate response if enabled
        if let Some(validator) = &self.validator {
            let validation_result = validator.validate(&response).await?;
            if validation_result.has_errors() {
                anyhow::bail!("Response validation failed: {:?}", validation_result.issues);
            }
        }

        // Record metrics if enabled
        if let Some(metrics) = &self.metrics {
            let duration = start_time.elapsed().as_secs_f64();
            let tokens = response
                .usage
                .as_ref()
                .map(|u| u.total_tokens as i64)
                .unwrap_or(0);
            metrics
                .record_request(&request.model, "success", tokens, duration)
                .await;
        }

        Ok(response)
    }

    /// Send a streaming request to a model.
    ///
    /// # Arguments
    ///
    /// * `content` - The message content to send
    /// * `model` - The model to use
    ///
    /// # Returns
    ///
    /// A stream of response chunks.
    pub async fn send_streaming_message(
        &self,
        content: &str,
        model: &str,
    ) -> Result<impl futures::Stream<Item = Result<String>>> {
        let request = ModelRequest {
            model: model.to_string(),
            messages: vec![crate::provider::Message {
                role: "user".to_string(),
                content: content.to_string(),
            }],
            temperature: None,
            max_tokens: None,
            stream: Some(true),
        };

        let provider = self
            .registry
            .get(&request.model)
            .ok_or_else(|| anyhow::anyhow!("No provider found for model: {}", request.model))?;

        let stream = provider.process_streaming_request(request).await?;

        Ok(stream.map(|chunk| {
            chunk.map(|c| c.content).map_err(|e| anyhow::anyhow!("Stream error: {}", e))
        }))
    }

    /// Get current metrics if enabled.
    pub async fn get_metrics(&self) -> Option<String> {
        self.metrics.as_ref().map(|m| m.collect_metrics())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[tokio::test]
    async fn test_client_creation() {
        let config = ClientConfig {
            providers: vec![ProviderConfig {
                name: "openai".to_string(),
                api_key: "test-key".to_string(),
                endpoint: None,
            }],
            cache_enabled: true,
            validation_enabled: true,
            optimization_enabled: true,
            metrics_enabled: true,
        };

        let client = ModelGuardClient::new(config).await;
        assert!(client.is_ok());
    }

    #[tokio::test]
    async fn test_message_sending() {
        let mut registry = ProviderRegistry::new();
        registry.register(
            "test".to_string(),
            Box::new(TestProvider {
                responses: Arc::new(tokio::sync::RwLock::new(vec![ModelResponse {
                    content: "test response".to_string(),
                    model: "test-model".to_string(),
                    usage: None,
                }])),
            }),
        );

        let client = ModelGuardClient {
            registry: Arc::new(registry),
            cache: None,
            validator: None,
            optimizer: None,
            metrics: None,
        };

        let response = client.send_message("test message", "test").await;
        assert!(response.is_ok());
        assert_eq!(response.unwrap().content, "test response");
    }

    struct TestProvider {
        responses: Arc<tokio::sync::RwLock<Vec<ModelResponse>>>,
    }

    #[async_trait::async_trait]
    impl ModelProvider for TestProvider {
        async fn process_request(&self, _request: ModelRequest) -> Result<ModelResponse> {
            let responses = self.responses.read().await;
            Ok(responses[0].clone())
        }

        fn get_credentials(&self) -> HashMap<String, String> {
            HashMap::new()
        }

        fn supports_model(&self, _model: &str) -> bool {
            true
        }
    }
}