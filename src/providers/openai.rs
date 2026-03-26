use crate::provider::{Message, ModelProvider, ModelRequest, ModelResponse};
use async_trait::async_trait;
use reqwest::Client;
use std::collections::HashMap;

pub struct OpenAIProvider {
    client: Client,
    api_key: String,
}

impl OpenAIProvider {
    pub fn new(api_key: String) -> Self {
        Self {
            client: Client::new(),
            api_key,
        }
    }
}

#[async_trait]
impl ModelProvider for OpenAIProvider {
    async fn process_request(&self, request: ModelRequest) -> anyhow::Result<ModelResponse> {
        let response = self
            .client
            .post("https://api.openai.com/v1/chat/completions")
            .header("Authorization", format!("Bearer {}", self.api_key))
            .json(&request)
            .send()
            .await?;

        let result = response.json::<ModelResponse>().await?;
        Ok(result)
    }

    fn get_credentials(&self) -> HashMap<String, String> {
        let mut creds = HashMap::new();
        creds.insert("OPENAI_API_KEY".to_string(), self.api_key.clone());
        creds
    }

    fn supports_model(&self, model: &str) -> bool {
        model.starts_with("gpt-") || model.contains("openai")
    }
}