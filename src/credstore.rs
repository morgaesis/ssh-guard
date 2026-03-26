use anyhow::Result;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialStoreConfig {
    pub store_type: StoreType,
    pub endpoint: String,
    pub namespace: Option<String>,
    pub auth_config: AuthConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StoreType {
    Vault,
    AwsSecretsManager,
    AzureKeyVault,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuthConfig {
    Vault {
        token: Option<String>,
        role_id: Option<String>,
        secret_id: Option<String>,
    },
    Aws {
        region: String,
        profile: Option<String>,
    },
    Azure {
        tenant_id: String,
        client_id: String,
        client_secret: String,
    },
}

#[async_trait]
pub trait CredentialStore: Send + Sync {
    async fn get_credentials(&self, path: &str) -> Result<HashMap<String, String>>;
    async fn list_credentials(&self, prefix: &str) -> Result<Vec<String>>;
}

pub struct VaultStore {
    client: reqwest::Client,
    config: CredentialStoreConfig,
    token: String,
}

impl VaultStore {
    pub async fn new(config: CredentialStoreConfig) -> Result<Self> {
        let client = reqwest::Client::new();
        let token = match &config.auth_config {
            AuthConfig::Vault {
                token: Some(t), ..
            } => t.clone(),
            AuthConfig::Vault {
                role_id: Some(role),
                secret_id: Some(secret),
                ..
            } => {
                // Perform AppRole authentication
                let auth_payload = serde_json::json!({
                    "role_id": role,
                    "secret_id": secret,
                });

                let response = client
                    .post(format!("{}/v1/auth/approle/login", config.endpoint))
                    .json(&auth_payload)
                    .send()
                    .await?
                    .json::<serde_json::Value>()
                    .await?;

                response["auth"]["client_token"]
                    .as_str()
                    .ok_or_else(|| anyhow::anyhow!("Invalid Vault authentication response"))?
                    .to_string()
            }
            _ => anyhow::bail!("Invalid Vault authentication configuration"),
        };

        Ok(Self {
            client,
            config,
            token,
        })
    }
}

#[async_trait]
impl CredentialStore for VaultStore {
    async fn get_credentials(&self, path: &str) -> Result<HashMap<String, String>> {
        let url = format!("{}/v1/{}", self.config.endpoint, path);
        let response = self
            .client
            .get(&url)
            .header("X-Vault-Token", &self.token)
            .send()
            .await?
            .json::<serde_json::Value>()
            .await?;

        let data = response["data"]["data"]
            .as_object()
            .ok_or_else(|| anyhow::anyhow!("Invalid Vault response format"))?;

        let mut creds = HashMap::new();
        for (key, value) in data {
            if let Some(v) = value.as_str() {
                creds.insert(key.clone(), v.to_string());
            }
        }

        Ok(creds)
    }

    async fn list_credentials(&self, prefix: &str) -> Result<Vec<String>> {
        let url = format!("{}/v1/{}?list=true", self.config.endpoint, prefix);
        let response = self
            .client
            .get(&url)
            .header("X-Vault-Token", &self.token)
            .send()
            .await?
            .json::<serde_json::Value>()
            .await?;

        let keys = response["data"]["keys"]
            .as_array()
            .ok_or_else(|| anyhow::anyhow!("Invalid Vault list response format"))?;

        let mut paths = Vec::new();
        for key in keys {
            if let Some(path) = key.as_str() {
                paths.push(path.to_string());
            }
        }

        Ok(paths)
    }
}

pub struct AwsSecretsStore {
    client: aws_sdk_secretsmanager::Client,
    config: CredentialStoreConfig,
}

impl AwsSecretsStore {
    pub async fn new(config: CredentialStoreConfig) -> Result<Self> {
        let aws_config = match &config.auth_config {
            AuthConfig::Aws { region, profile } => {
                let mut builder = aws_config::from_env();
                if let Some(p) = profile {
                    builder = builder.profile_name(p);
                }
                builder.region(region).load().await
            }
            _ => anyhow::bail!("Invalid AWS authentication configuration"),
        };

        let client = aws_sdk_secretsmanager::Client::new(&aws_config);

        Ok(Self { client, config })
    }
}

#[async_trait]
impl CredentialStore for AwsSecretsStore {
    async fn get_credentials(&self, path: &str) -> Result<HashMap<String, String>> {
        let response = self
            .client
            .get_secret_value()
            .secret_id(path)
            .send()
            .await?;

        let secret = response
            .secret_string()
            .ok_or_else(|| anyhow::anyhow!("Secret not found"))?;

        let creds: HashMap<String, String> = serde_json::from_str(secret)?;
        Ok(creds)
    }

    async fn list_credentials(&self, prefix: &str) -> Result<Vec<String>> {
        let mut paths = Vec::new();
        let mut next_token = None;

        loop {
            let mut req = self.client.list_secrets();
            if let Some(token) = next_token {
                req = req.next_token(token);
            }

            let response = req.send().await?;
            if let Some(secrets) = response.secret_list() {
                for secret in secrets {
                    if let Some(name) = secret.name() {
                        if name.starts_with(prefix) {
                            paths.push(name.to_string());
                        }
                    }
                }
            }

            match response.next_token() {
                Some(token) => next_token = Some(token.to_string()),
                None => break,
            }
        }

        Ok(paths)
    }
}

pub struct AzureKeyVaultStore {
    client: reqwest::Client,
    config: CredentialStoreConfig,
    token: String,
}

impl AzureKeyVaultStore {
    pub async fn new(config: CredentialStoreConfig) -> Result<Self> {
        let client = reqwest::Client::new();

        let token = match &config.auth_config {
            AuthConfig::Azure {
                tenant_id,
                client_id,
                client_secret,
            } => {
                let auth_url = format!(
                    "https://login.microsoftonline.com/{}/oauth2/v2.0/token",
                    tenant_id
                );

                let params = [
                    ("grant_type", "client_credentials"),
                    ("client_id", client_id),
                    ("client_secret", client_secret),
                    (
                        "scope",
                        "https://vault.azure.net/.default",
                    ),
                ];

                let response = client
                    .post(&auth_url)
                    .form(&params)
                    .send()
                    .await?
                    .json::<serde_json::Value>()
                    .await?;

                response["access_token"]
                    .as_str()
                    .ok_or_else(|| anyhow::anyhow!("Invalid Azure authentication response"))?
                    .to_string()
            }
            _ => anyhow::bail!("Invalid Azure authentication configuration"),
        };

        Ok(Self {
            client,
            config,
            token,
        })
    }
}

#[async_trait]
impl CredentialStore for AzureKeyVaultStore {
    async fn get_credentials(&self, path: &str) -> Result<HashMap<String, String>> {
        let url = format!(
            "{}/secrets/{}?api-version=7.3",
            self.config.endpoint,
            path
        );

        let response = self
            .client
            .get(&url)
            .header("Authorization", format!("Bearer {}", self.token))
            .send()
            .await?
            .json::<serde_json::Value>()
            .await?;

        let value = response["value"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("Invalid Azure Key Vault response format"))?;

        let creds: HashMap<String, String> = serde_json::from_str(value)?;
        Ok(creds)
    }

    async fn list_credentials(&self, prefix: &str) -> Result<Vec<String>> {
        let url = format!(
            "{}/secrets?api-version=7.3",
            self.config.endpoint
        );

        let response = self
            .client
            .get(&url)
            .header("Authorization", format!("Bearer {}", self.token))
            .send()
            .await?
            .json::<serde_json::Value>()
            .await?;

        let mut paths = Vec::new();
        if let Some(values) = response["value"].as_array() {
            for value in values {
                if let Some(id) = value["id"].as_str() {
                    if id.contains(prefix) {
                        paths.push(id.to_string());
                    }
                }
            }
        }

        Ok(paths)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mockito::mock;

    #[tokio::test]
    async fn test_vault_authentication() {
        let mut server = mockito::Server::new();

        let mock = mock("POST", "/v1/auth/approle/login")
            .with_status(200)
            .with_body(r#"{"auth": {"client_token": "test-token"}}"#)
            .create();

        let config = CredentialStoreConfig {
            store_type: StoreType::Vault,
            endpoint: server.url(),
            namespace: None,
            auth_config: AuthConfig::Vault {
                token: None,
                role_id: Some("test-role".to_string()),
                secret_id: Some("test-secret".to_string()),
            },
        };

        let store = VaultStore::new(config).await;
        assert!(store.is_ok());
        mock.assert();
    }

    #[tokio::test]
    async fn test_vault_get_credentials() {
        let mut server = mockito::Server::new();

        let mock = mock("GET", "/v1/secret/data/test")
            .with_status(200)
            .with_body(r#"{"data": {"data": {"key": "value"}}}"#)
            .create();

        let config = CredentialStoreConfig {
            store_type: StoreType::Vault,
            endpoint: server.url(),
            namespace: None,
            auth_config: AuthConfig::Vault {
                token: Some("test-token".to_string()),
                role_id: None,
                secret_id: None,
            },
        };

        let store = VaultStore::new(config).await.unwrap();
        let creds = store.get_credentials("secret/data/test").await.unwrap();

        assert_eq!(creds.get("key").unwrap(), "value");
        mock.assert();
    }
}