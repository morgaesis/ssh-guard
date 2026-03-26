use async_trait::async_trait;
use futures::Stream;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, pin::Pin};
use crate::streaming::StreamChunk;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelRequest {
    pub model: String,
    pub messages: Vec<Message>,
    pub temperature: Option<f32>,
    pub max_tokens: Option<u32>,
    pub stream: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    pub role: String,
    pub content: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelResponse {
    pub content: String,
    pub model: String,
    pub usage: Option<Usage>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Usage {
    pub prompt_tokens: u32,
    pub completion_tokens: u32,
    pub total_tokens: u32,
}

#[async_trait]
pub trait ModelProvider: Send + Sync {
    async fn process_request(&self, request: ModelRequest) -> anyhow::Result<ModelResponse>;

    async fn process_streaming_request(
        &self,
        request: ModelRequest,
    ) -> anyhow::Result<Pin<Box<dyn Stream<Item = anyhow::Result<StreamChunk>> + Send>>> {
        // Default implementation falls back to non-streaming
        let response = self.process_request(request).await?;
        Ok(Box::pin(futures::stream::once(async move {
            Ok(StreamChunk {
                content: response.content,
                finish_reason: Some("stop".to_string()),
            })
        })))
    }

    fn get_credentials(&self) -> HashMap<String, String>;
    fn supports_model(&self, model: &str) -> bool;
    fn supports_streaming(&self) -> bool {
        false
    }
}

pub struct ProviderRegistry {
    providers: HashMap<String, Box<dyn ModelProvider>>,
}

impl ProviderRegistry {
    pub fn new() -> Self {
        Self {
            providers: HashMap::new(),
        }
    }

    pub fn register(&mut self, name: String, provider: Box<dyn ModelProvider>) {
        self.providers.insert(name, provider);
    }

    pub fn get(&self, name: &str) -> Option<&dyn ModelProvider> {
        self.providers.get(name).map(|p| p.as_ref())
    }

    pub fn list_providers(&self) -> Vec<String> {
        self.providers.keys().cloned().collect()
    }
}