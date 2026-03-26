use crate::provider::{Message, ModelProvider, ModelRequest, ModelResponse};
use async_trait::async_trait;
use reqwest::Client;
use std::collections::HashMap;

pub struct ClaudeProvider {
    client: Client,
    api_key: String,
}

impl ClaudeProvider {
    pub fn new(api_key: String) -> Self {
        Self {
            client: Client::new(),
            api_key,
        }
    }
}

#[async_trait]
impl ModelProvider for ClaudeProvider {
    async fn process_request(&self, request: ModelRequest) -> anyhow::Result<ModelResponse> {
        let response = self
            .client
            .post("https://api.anthropic.com/v1/messages")
            .header("x-api-key", &self.api_key)
            .header("anthropic-version", "2023-06-01")
            .json(&request)
            .send()
            .await?;

        let result = response.json::<ModelResponse>().await?;
        Ok(result)
    }

    fn get_credentials(&self) -> HashMap<String, String> {
        let mut creds = HashMap::new();
        creds.insert("ANTHROPIC_API_KEY".to_string(), self.api_key.clone());
        creds
    }

    fn supports_model(&self, model: &str) -> bool {
        model.starts_with("claude-") || model.contains("anthropic")
    }
}