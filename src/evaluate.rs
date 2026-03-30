use crate::policy::PolicyEngine;
use anyhow::{bail, Context, Result};
use reqwest::header::{HeaderMap, HeaderName, HeaderValue, AUTHORIZATION, CONTENT_TYPE};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::Duration;

const SYSTEM_PROMPT: &str = r#"You evaluate SSH commands for safety. Your job is to block dangerous operations while letting agents get work done.

Think about each command like a security guard reviewing a request:

1. WHAT is being modified? (files, processes, network, system config)
2. WHERE does it affect? (user files vs system-wide)
3. HOW does it execute? (direct vs piped to shell)
4. IS this a means to gain elevated privileges?

DENY when there's clear risk of:
- Data destruction (mass deletion, disk wipe, format)
- Getting a root shell or root access (sudo su, sudo -i, su root)
- Disabling security controls (flushing iptables, stopping firewall)
- Service disruption (stopping ssh, critical services)
- Remote code execution (piping curl/wget to shell)
- Self-replicating harm (fork bombs)

ALLOW when it's routine administration:
- Reading files, checking system state, monitoring
- Running commands with sudo for legitimate tasks (sudo apt, sudo systemctl)
- Common admin tasks (service restarts, package management)
- Container and orchestration queries
- Network debugging

A command being unusual or clever is not grounds for denial.

Respond with JSON only: {"decision": "APPROVE|DENY", "reason": "brief explanation", "risk": 0-10}"#;

const DEFAULT_MODEL: &str = "google/gemini-2.0-flash-001";
const DEFAULT_TIMEOUT: u64 = 10;
const DEFAULT_API_URL: &str = "https://openrouter.ai/api/v1/chat/completions";

#[derive(Debug, Clone)]
pub struct LlmConfig {
    pub enabled: bool,
    pub api_key: Option<String>,
    pub api_url: Option<String>,
    pub model: Option<String>,
    pub timeout_secs: u64,
}

impl Default for LlmConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            api_key: None,
            api_url: None,
            model: None,
            timeout_secs: DEFAULT_TIMEOUT,
        }
    }
}

impl LlmConfig {
    pub fn api_url(&self) -> String {
        self.api_url
            .clone()
            .unwrap_or_else(|| DEFAULT_API_URL.to_string())
    }

    pub fn model(&self) -> String {
        self.model
            .clone()
            .unwrap_or_else(|| DEFAULT_MODEL.to_string())
    }

    pub fn timeout(&self) -> Duration {
        Duration::from_secs(self.timeout_secs)
    }
}

#[derive(Debug, Clone, Default)]
pub struct EvalConfig {
    pub policy_path: Option<PathBuf>,
    pub llm: LlmConfig,
}

impl EvalConfig {
    pub fn policy_path(mut self, path: PathBuf) -> Self {
        self.policy_path = Some(path);
        self
    }

    pub fn llm_enabled(mut self, enabled: bool) -> Self {
        self.llm.enabled = enabled;
        self
    }

    pub fn llm_api_key(mut self, key: String) -> Self {
        self.llm.api_key = Some(key);
        self
    }

    pub fn llm_api_url(mut self, url: String) -> Self {
        self.llm.api_url = Some(url);
        self
    }

    pub fn llm_model(mut self, model: String) -> Self {
        self.llm.model = Some(model);
        self
    }

    pub fn llm_timeout_secs(mut self, secs: u64) -> Self {
        self.llm.timeout_secs = secs;
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LlmResponse {
    pub decision: String,
    pub reason: String,
    pub risk: i32,
}

#[derive(Debug, Clone)]
pub enum EvalResult {
    Allow { reason: String, source: EvalSource },
    Deny { reason: String, source: EvalSource },
    Error(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvalSource {
    StaticPolicy,
    Llm,
}

impl std::fmt::Display for EvalResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EvalResult::Allow { reason, source } => {
                write!(f, "Allow ({:?}): {}", source, reason)
            }
            EvalResult::Deny { reason, source } => {
                write!(f, "Deny ({:?}): {}", source, reason)
            }
            EvalResult::Error(e) => {
                write!(f, "Error: {}", e)
            }
        }
    }
}

impl EvalResult {
    pub fn is_allow(&self) -> bool {
        matches!(self, EvalResult::Allow { .. })
    }

    pub fn is_deny(&self) -> bool {
        matches!(self, EvalResult::Deny { .. })
    }

    pub fn is_error(&self) -> bool {
        matches!(self, EvalResult::Error(_))
    }

    pub fn reason(&self) -> String {
        match self {
            EvalResult::Allow { reason, .. } => reason.clone(),
            EvalResult::Deny { reason, .. } => reason.clone(),
            EvalResult::Error(e) => format!("LLM unavailable: {}", e),
        }
    }
}

pub struct Evaluator {
    policy_engine: Option<PolicyEngine>,
    llm_config: LlmConfig,
    http_client: Client,
}

impl Evaluator {
    pub fn new(config: EvalConfig) -> Result<Self> {
        let policy_engine = if let Some(ref path) = config.policy_path {
            if !path.exists() {
                bail!("policy file does not exist: {}", path.display());
            }
            Some(PolicyEngine::load_file(path).context("failed to load policy file")?)
        } else {
            None
        };

        let http_client = Client::builder()
            .timeout(config.llm.timeout())
            .build()
            .context("failed to create HTTP client")?;

        Ok(Self {
            policy_engine,
            llm_config: config.llm,
            http_client,
        })
    }

    pub fn has_static_policy(&self) -> bool {
        if let Some(ref engine) = self.policy_engine {
            !engine.allow_list().is_empty() || !engine.deny_list().is_empty()
        } else {
            false
        }
    }

    pub async fn validate(&self) -> Result<()> {
        if let Some(ref engine) = self.policy_engine {
            if !engine.allow_list().is_empty() || !engine.deny_list().is_empty() {
                tracing::debug!("static policy has explicit rules");
            }
        }

        if self.llm_config.enabled {
            if self.llm_config.api_key.is_none() {
                bail!("llm_enabled but llm_api_key not provided");
            }

            if let Err(e) = self.ping_llm().await {
                bail!("LLM connectivity check failed: {}", e);
            }
        }

        Ok(())
    }

    async fn ping_llm(&self) -> Result<()> {
        let api_key = self
            .llm_config
            .api_key
            .as_ref()
            .context("API key required")?;

        let url = format!(
            "{}/models",
            self.llm_config
                .api_url
                .as_ref()
                .map(|u| u.trim_end_matches('/').to_string())
                .unwrap_or_else(|| DEFAULT_API_URL
                    .split('/')
                    .take(3)
                    .collect::<Vec<_>>()
                    .join("/"))
        );

        let response = self
            .http_client
            .get(&url)
            .header("Authorization", format!("Bearer {}", api_key))
            .timeout(Duration::from_secs(5))
            .send()
            .await;

        match response {
            Ok(resp) if resp.status().is_success() => {
                tracing::debug!("LLM connectivity check passed");
                Ok(())
            }
            Ok(resp) => {
                let status = resp.status();
                let body = resp.text().await.unwrap_or_default();
                tracing::warn!("LLM API returned {}: {}", status, body);
                Ok(())
            }
            Err(e) => {
                tracing::warn!("LLM connectivity check failed: {}", e);
                Err(e.into())
            }
        }
    }

    pub async fn evaluate(&self, command: &str, host: &str) -> EvalResult {
        if self.has_static_policy() {
            return self.evaluate_static(command);
        }

        if self.llm_config.enabled {
            return self.evaluate_llm(command, host).await;
        }

        EvalResult::Deny {
            reason: "no policy and LLM disabled: default-deny".to_string(),
            source: EvalSource::StaticPolicy,
        }
    }

    fn evaluate_static(&self, command: &str) -> EvalResult {
        let engine = match &self.policy_engine {
            Some(e) => e,
            None => {
                return EvalResult::Deny {
                    reason: "no static policy configured".to_string(),
                    source: EvalSource::StaticPolicy,
                }
            }
        };

        let result = engine.check(command);

        if result.is_allowed() {
            EvalResult::Allow {
                reason: result.reason,
                source: EvalSource::StaticPolicy,
            }
        } else {
            EvalResult::Deny {
                reason: result.reason,
                source: EvalSource::StaticPolicy,
            }
        }
    }

    async fn evaluate_llm(&self, command: &str, host: &str) -> EvalResult {
        let api_key = match &self.llm_config.api_key {
            Some(k) => k.clone(),
            None => {
                return EvalResult::Error("LLM API key not configured".to_string());
            }
        };

        let user_message = format!("Host: {}\nCommand: {}", host, command);

        let body = serde_json::json!({
            "model": self.llm_config.model(),
            "max_tokens": 512,
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_message}
            ]
        });

        let api_url = self.llm_config.api_url();
        let body_str = serde_json::to_string(&body).unwrap_or_default();

        tracing::debug!("LLM request to {}", api_url);

        let output = tokio::process::Command::new("curl")
            .args([
                "-s",
                "-X",
                "POST",
                &api_url,
                "-H",
                &format!("Authorization: Bearer {}", api_key),
                "-H",
                "Content-Type: application/json",
                "-d",
                &body_str,
            ])
            .output()
            .await;

        let output = match output {
            Ok(o) => o,
            Err(e) => {
                return EvalResult::Error(format!("failed to execute curl: {}", e));
            }
        };

        let response_text = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();

        tracing::debug!("LLM response: {}", response_text);
        if !stderr.is_empty() {
            tracing::warn!("LLM stderr: {}", stderr);
        }

        if !output.status.success() {
            return EvalResult::Error(format!(
                "LLM curl error ({}): {}",
                output.status.code().unwrap_or(-1),
                response_text
            ));
        }

        let decision = match self.parse_llm_response(&response_text) {
            Ok(d) => d,
            Err(e) => {
                tracing::error!("failed to parse LLM response: {}", e);
                return EvalResult::Error(e.to_string());
            }
        };

        if decision.decision == "APPROVE" {
            EvalResult::Allow {
                reason: decision.reason,
                source: EvalSource::Llm,
            }
        } else {
            EvalResult::Deny {
                reason: decision.reason,
                source: EvalSource::Llm,
            }
        }
    }

    fn parse_llm_response(&self, response_text: &str) -> Result<LlmResponse> {
        let parsed: serde_json::Value = serde_json::from_str(response_text)?;

        let arguments = parsed
            .pointer("/choices/0/message/content")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("no content in response"))?;

        let json_str = extract_json(arguments)?;

        let response: LlmResponse = serde_json::from_str(&json_str)?;

        Ok(response)
    }
}

fn extract_json(text: &str) -> Result<String> {
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(text) {
        return serde_json::to_string(&v).map_err(|_| anyhow::anyhow!("failed to reserialize"));
    }

    if let Some(start) = text.find('{') {
        if let Some(end) = text[start..].find('}') {
            let candidate = &text[start..=start + end];
            if serde_json::from_str::<serde_json::Value>(candidate).is_ok() {
                return Ok(candidate.to_string());
            }
        }
    }

    bail!("no valid JSON found in response")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_eval_result_display() {
        let allow = EvalResult::Allow {
            reason: "test".to_string(),
            source: EvalSource::Llm,
        };
        assert!(allow.to_string().contains("Allow"));
        assert!(allow.to_string().contains("Llm"));

        let deny = EvalResult::Deny {
            reason: "test".to_string(),
            source: EvalSource::StaticPolicy,
        };
        assert!(deny.to_string().contains("Deny"));
        assert!(deny.to_string().contains("StaticPolicy"));

        let err = EvalResult::Error("test error".to_string());
        assert!(err.to_string().contains("Error"));
        assert!(err.to_string().contains("test error"));
    }

    #[test]
    fn test_eval_result_helpers() {
        let allow = EvalResult::Allow {
            reason: "test".to_string(),
            source: EvalSource::Llm,
        };
        assert!(allow.is_allow());
        assert!(!allow.is_deny());
        assert!(!allow.is_error());

        let deny = EvalResult::Deny {
            reason: "test".to_string(),
            source: EvalSource::StaticPolicy,
        };
        assert!(!deny.is_allow());
        assert!(deny.is_deny());
        assert!(!deny.is_error());

        let err = EvalResult::Error("test".to_string());
        assert!(!err.is_allow());
        assert!(!err.is_deny());
        assert!(err.is_error());
    }

    #[test]
    fn test_llm_config_defaults() {
        let config = LlmConfig::default();
        assert!(config.enabled);
        assert!(config.api_url.is_none());
        assert!(config.model.is_none());
        assert_eq!(config.timeout_secs, DEFAULT_TIMEOUT);
        assert_eq!(config.model(), DEFAULT_MODEL);
        assert_eq!(config.api_url(), DEFAULT_API_URL);
    }

    #[test]
    fn test_llm_config_builder() {
        let config = LlmConfig {
            enabled: false,
            api_key: Some("test-key".to_string()),
            model: Some("test-model".to_string()),
            ..Default::default()
        };

        assert!(!config.enabled);
        assert_eq!(config.api_key.as_deref(), Some("test-key"));
        assert_eq!(config.model(), "test-model");
    }

    #[test]
    fn test_eval_config_builder() {
        let config = EvalConfig::default()
            .policy_path(PathBuf::from("/test/policy.yaml"))
            .llm_enabled(false)
            .llm_api_key("key".to_string())
            .llm_timeout_secs(30);

        assert_eq!(
            config.policy_path.as_ref().unwrap().to_str(),
            Some("/test/policy.yaml")
        );
        assert!(!config.llm.enabled);
        assert_eq!(config.llm.api_key.as_deref(), Some("key"));
        assert_eq!(config.llm.timeout_secs, 30);
    }

    #[test]
    fn test_extract_json_direct() {
        let json = r#"{"decision": "APPROVE", "reason": "safe", "risk": 1}"#;
        let extracted = extract_json(json).unwrap();
        assert!(extracted.contains("APPROVE"));
    }

    #[test]
    fn test_extract_json_embedded() {
        let text =
            r#"Here is the result: {"decision": "DENY", "reason": "dangerous", "risk": 8} thanks!"#;
        let extracted = extract_json(text).unwrap();
        assert!(extracted.contains("DENY"));
    }

    #[test]
    fn test_extract_json_invalid() {
        let text = "not json at all";
        assert!(extract_json(text).is_err());
    }
}
