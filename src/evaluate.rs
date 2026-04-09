use crate::policy::{PolicyEngine, PolicyMode};
use anyhow::{bail, Context, Result};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::Duration;

/// Default system prompt (balanced mode), compiled from config/system-prompt.md.
/// Override at runtime with `--system-prompt <path>` or `~/.config/guard/system-prompt.txt`.
const SYSTEM_PROMPT: &str = include_str!("../config/system-prompt.md");

/// SAFE mode prompt: allow almost everything, rely on env_clear + output redaction.
const SYSTEM_PROMPT_SAFE: &str = include_str!("../config/system-prompt-safe.md");

/// PARANOID mode prompt: block everything except basic read-only inspection.
const SYSTEM_PROMPT_PARANOID: &str = include_str!("../config/system-prompt-paranoid.md");

const DEFAULT_MODEL: &str = "google/gemini-3-flash-preview";
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
    pub mode: Option<PolicyMode>,
    pub llm: LlmConfig,
    /// Path to a custom system prompt file. If set, overrides the compiled-in prompt.
    pub system_prompt_path: Option<PathBuf>,
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

    pub fn mode(mut self, mode: PolicyMode) -> Self {
        self.mode = Some(mode);
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

    pub fn system_prompt_path(mut self, path: PathBuf) -> Self {
        self.system_prompt_path = Some(path);
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
    system_prompt: String,
}

impl Evaluator {
    pub fn new(config: EvalConfig) -> Result<Self> {
        let policy_engine = if let Some(ref path) = config.policy_path {
            if !path.exists() {
                bail!("policy file does not exist: {}", path.display());
            }
            Some(PolicyEngine::load_file(path).context("failed to load policy file")?)
        } else {
            config.mode.map(PolicyEngine::from_mode)
        };

        // Load system prompt. Priority:
        // 1. --system-prompt <path> (explicit override)
        // 2. ~/.config/guard/system-prompt.txt (user customization)
        // 3. Mode-specific compiled prompt (safe/paranoid/default)
        let system_prompt = if let Some(ref path) = config.system_prompt_path {
            std::fs::read_to_string(path)
                .with_context(|| format!("failed to read system prompt from {}", path.display()))?
        } else {
            let default_path =
                dirs::config_dir().map(|d| d.join("guard").join("system-prompt.txt"));
            match default_path {
                Some(p) if p.exists() => {
                    tracing::info!("Loading system prompt from {}", p.display());
                    std::fs::read_to_string(&p).with_context(|| {
                        format!("failed to read system prompt from {}", p.display())
                    })?
                }
                _ => {
                    // Select compiled prompt based on mode
                    match config.mode {
                        Some(PolicyMode::Safe) => {
                            tracing::info!("Using SAFE mode system prompt");
                            SYSTEM_PROMPT_SAFE.to_string()
                        }
                        Some(PolicyMode::Paranoid) => {
                            tracing::info!("Using PARANOID mode system prompt");
                            SYSTEM_PROMPT_PARANOID.to_string()
                        }
                        _ => SYSTEM_PROMPT.to_string(),
                    }
                }
            }
        };

        let http_client = Client::builder()
            .timeout(config.llm.timeout())
            .build()
            .context("failed to create HTTP client")?;

        Ok(Self {
            policy_engine,
            llm_config: config.llm,
            http_client,
            system_prompt,
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

    pub async fn evaluate(&self, command: &str) -> EvalResult {
        if let Some(ref engine) = self.policy_engine {
            let static_result = engine.check(command);
            if static_result.is_denied() {
                tracing::debug!("static policy denied: {}", static_result.reason);
                return EvalResult::Deny {
                    reason: static_result.reason,
                    source: EvalSource::StaticPolicy,
                };
            }
        }

        if self.llm_config.enabled {
            return self.evaluate_llm(command).await;
        }

        if let Some(ref engine) = self.policy_engine {
            let static_result = engine.check(command);
            if static_result.is_allowed() {
                return EvalResult::Allow {
                    reason: static_result.reason,
                    source: EvalSource::StaticPolicy,
                };
            }
        }

        EvalResult::Deny {
            reason: "no policy and LLM disabled: default-deny".to_string(),
            source: EvalSource::StaticPolicy,
        }
    }

    async fn evaluate_llm(&self, command: &str) -> EvalResult {
        let api_key = match &self.llm_config.api_key {
            Some(k) => k.clone(),
            None => {
                return EvalResult::Error("LLM API key not configured".to_string());
            }
        };

        let user_message = format!("Command: {}", command);

        let body = serde_json::json!({
            "model": self.llm_config.model(),
            "max_tokens": 512,
            "messages": [
                {"role": "system", "content": self.system_prompt},
                {"role": "user", "content": user_message}
            ]
        });

        let api_url = self.llm_config.api_url();

        tracing::debug!("LLM request to {}", api_url);

        let response = self
            .http_client
            .post(&api_url)
            .header("Authorization", format!("Bearer {}", api_key))
            .header("Content-Type", "application/json")
            .json(&body)
            .send()
            .await;

        let response = match response {
            Ok(r) => r,
            Err(e) => {
                return EvalResult::Error(format!("LLM request failed: {}", e));
            }
        };

        let status = response.status();
        let response_text = match response.text().await {
            Ok(t) => t,
            Err(e) => {
                return EvalResult::Error(format!("failed to read LLM response: {}", e));
            }
        };

        tracing::debug!(
            "LLM response ({}): {}...",
            status,
            &response_text[..response_text.len().min(200)]
        );

        if !status.is_success() {
            return EvalResult::Error(format!("LLM API error ({}): {}", status, response_text));
        }

        // Log token usage from the API response
        if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&response_text) {
            if let Some(usage) = parsed.get("usage") {
                let prompt_tokens = usage
                    .get("prompt_tokens")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);
                let completion_tokens = usage
                    .get("completion_tokens")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);
                let total_tokens = usage
                    .get("total_tokens")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);
                tracing::info!(
                    "[LLM_USAGE] model={} prompt_tokens={} completion_tokens={} total_tokens={}",
                    self.llm_config.model(),
                    prompt_tokens,
                    completion_tokens,
                    total_tokens,
                );
            }
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
