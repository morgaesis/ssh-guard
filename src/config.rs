use crate::cli::Mode;
use anyhow::{bail, Result};
use std::env;
use std::path::PathBuf;

/// All resolved configuration for ssh-guard.
pub struct Config {
    pub ssh_bin: String,
    pub api_url: String,
    pub api_key: String,
    pub model: String,
    pub api_type: ApiType,
    pub max_tokens: u32,
    pub timeout: u64,
    pub log_file: Option<String>,
    pub passthrough: Vec<String>,
    pub mode: Mode,
    pub redact: bool,
    pub prompt_override: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApiType {
    OpenAI,
    Anthropic,
}

impl std::str::FromStr for ApiType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "openai" => Ok(ApiType::OpenAI),
            "anthropic" => Ok(ApiType::Anthropic),
            other => Err(format!(
                "unknown API type '{}'. Use: openai, anthropic",
                other
            )),
        }
    }
}

/// Walk up from CWD to /, collecting .env file paths, then load them
/// in reverse order so the closest .env file wins.
pub fn load_env_files() {
    let mut dir = match env::current_dir() {
        Ok(d) => d,
        Err(_) => return,
    };

    let mut env_files: Vec<PathBuf> = Vec::new();

    loop {
        let env_file = dir.join(".env");
        if env_file.is_file() {
            env_files.push(env_file);
        }
        if !dir.pop() {
            break;
        }
    }

    // Load in reverse order so closest .env wins (later loads override earlier)
    for path in env_files.iter().rev() {
        let _ = dotenvy::from_path(path);
    }
}

/// Build Config from environment variables, with CLI overrides applied.
pub fn load_config(mode_override: Option<Mode>) -> Result<Config> {
    let api_key = env::var("SSH_GUARD_API_KEY")
        .or_else(|_| env::var("OPENROUTER_API_KEY"))
        .unwrap_or_default();

    let mode_str = env::var("SSH_GUARD_MODE").unwrap_or_else(|_| "readonly".to_string());
    let env_mode: Mode = mode_str
        .parse()
        .map_err(|e: String| anyhow::anyhow!("{}", e))?;
    let mode = mode_override.unwrap_or(env_mode);

    let api_type_str = env::var("SSH_GUARD_API_TYPE").unwrap_or_else(|_| "openai".to_string());
    let api_type: ApiType = api_type_str
        .parse()
        .map_err(|e: String| anyhow::anyhow!("{}", e))?;

    let passthrough_str = env::var("SSH_GUARD_PASSTHROUGH").unwrap_or_default();
    let passthrough: Vec<String> = passthrough_str
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    let redact_str = env::var("SSH_GUARD_REDACT").unwrap_or_else(|_| "true".to_string());
    let redact = redact_str != "false";

    let max_tokens: u32 = env::var("SSH_GUARD_MAX_TOKENS")
        .unwrap_or_else(|_| "512".to_string())
        .parse()
        .unwrap_or(512);

    let timeout: u64 = env::var("SSH_GUARD_TIMEOUT")
        .unwrap_or_else(|_| "30".to_string())
        .parse()
        .unwrap_or(30);

    let prompt_override = env::var("SSH_GUARD_PROMPT").ok().filter(|s| !s.is_empty());
    let log_file = env::var("SSH_GUARD_LOG").ok().filter(|s| !s.is_empty());

    if api_key.is_empty() {
        bail!(
            "SSH_GUARD_API_KEY is not set. Cannot validate command.\n\
             Set it in your environment or a .env file."
        );
    }

    Ok(Config {
        ssh_bin: env::var("SSH_GUARD_SSH_BIN").unwrap_or_else(|_| "/usr/bin/ssh".to_string()),
        api_url: env::var("SSH_GUARD_API_URL")
            .unwrap_or_else(|_| "https://openrouter.ai/api/v1/chat/completions".to_string()),
        api_key,
        model: env::var("SSH_GUARD_MODEL")
            .unwrap_or_else(|_| "google/gemini-2.0-flash-001".to_string()),
        api_type,
        max_tokens,
        timeout,
        log_file,
        passthrough,
        mode,
        redact,
        prompt_override,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_api_type_from_str() {
        assert_eq!("openai".parse::<ApiType>().unwrap(), ApiType::OpenAI);
        assert_eq!("anthropic".parse::<ApiType>().unwrap(), ApiType::Anthropic);
        assert_eq!("OPENAI".parse::<ApiType>().unwrap(), ApiType::OpenAI);
        assert!("unknown".parse::<ApiType>().is_err());
    }

    #[test]
    fn test_load_env_files_does_not_panic() {
        // Just verify it doesn't crash; actual .env loading is integration-level
        load_env_files();
    }
}
