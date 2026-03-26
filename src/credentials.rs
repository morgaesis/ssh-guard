use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    env,
    path::{Path, PathBuf},
    sync::Arc,
};
use tokio::sync::RwLock;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialConfig {
    pub env_file: Option<PathBuf>,
    pub providers: HashMap<String, ProviderConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderConfig {
    pub credential_keys: Vec<String>,
    pub required_keys: Vec<String>,
}

pub struct CredentialManager {
    credentials: Arc<RwLock<HashMap<String, String>>>,
    config: CredentialConfig,
}

impl CredentialManager {
    pub fn new(config: CredentialConfig) -> Self {
        Self {
            credentials: Arc::new(RwLock::new(HashMap::new())),
            config,
        }
    }

    pub async fn load_credentials(&self) -> Result<()> {
        let mut creds = HashMap::new();

        // Load from environment
        for (key, value) in env::vars() {
            if self.is_credential_key(&key) {
                creds.insert(key, value);
            }
        }

        // Load from .env file if specified
        if let Some(env_path) = &self.config.env_file {
            if env_path.exists() {
                let content = tokio::fs::read_to_string(env_path).await?;
                for line in content.lines() {
                    if let Some((key, value)) = line.split_once('=') {
                        let key = key.trim();
                        if self.is_credential_key(key) {
                            creds.insert(key.to_string(), value.trim().to_string());
                        }
                    }
                }
            }
        }

        let mut credentials = self.credentials.write().await;
        *credentials = creds;
        Ok(())
    }

    fn is_credential_key(&self, key: &str) -> bool {
        for provider in self.config.providers.values() {
            if provider.credential_keys.iter().any(|k| key.contains(k)) {
                return true;
            }
        }
        false
    }

    pub async fn get_credentials(&self, provider: &str) -> Option<HashMap<String, String>> {
        let credentials = self.credentials.read().await;
        let provider_config = self.config.providers.get(provider)?;

        let mut result = HashMap::new();
        for key in &provider_config.credential_keys {
            for (cred_key, value) in credentials.iter() {
                if cred_key.contains(key) {
                    result.insert(cred_key.clone(), value.clone());
                }
            }
        }

        if provider_config.required_keys.iter().all(|k|
            result.iter().any(|(key, _)| key.contains(k))) {
            Some(result)
        } else {
            None
        }
    }

    pub async fn inject_credentials(&self, cmd: &str) -> String {
        let credentials = self.credentials.read().await;
        let mut result = cmd.to_string();

        // Sort by length descending to handle longer var names first
        let mut vars: Vec<_> = credentials.iter().collect();
        vars.sort_by(|a, b| b.0.len().cmp(&a.0.len()));

        for (key, value) in vars {
            let var_pattern = format!("${{{}}}", key);
            result = result.replace(&var_pattern, value);
        }

        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use tempfile::NamedTempFile;

    #[tokio::test]
    async fn test_credential_loading() {
        let mut config = CredentialConfig {
            env_file: None,
            providers: HashMap::new(),
        };

        let mut provider_config = ProviderConfig {
            credential_keys: vec!["API_KEY".to_string()],
            required_keys: vec!["API_KEY".to_string()],
        };
        config.providers.insert("test".to_string(), provider_config);

        env::set_var("TEST_API_KEY", "secret123");
        let manager = CredentialManager::new(config);
        manager.load_credentials().await.unwrap();

        let creds = manager.get_credentials("test").await.unwrap();
        assert!(creds.contains_key("TEST_API_KEY"));
        env::remove_var("TEST_API_KEY");
    }

    #[tokio::test]
    async fn test_credential_injection() {
        let mut config = CredentialConfig {
            env_file: None,
            providers: HashMap::new(),
        };

        let provider_config = ProviderConfig {
            credential_keys: vec!["TOKEN".to_string()],
            required_keys: vec!["TOKEN".to_string()],
        };
        config.providers.insert("test".to_string(), provider_config);

        let manager = CredentialManager::new(config);
        {
            let mut creds = manager.credentials.write().await;
            creds.insert("API_TOKEN".to_string(), "secret123".to_string());
        }

        let cmd = "curl -H 'Authorization: Bearer ${API_TOKEN}' https://api.example.com";
        let result = manager.inject_credentials(cmd).await;
        assert!(result.contains("secret123"));
        assert!(!result.contains("${API_TOKEN}"));
    }
}