use crate::config::{ApiType, Config};
use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Tool schema for structured LLM responses.
const TOOL_NAME: &str = "ssh_command_decision";
const TOOL_DESC: &str = "Approve or deny an SSH command based on the security policy.";

/// The decision returned by the LLM.
#[derive(Debug, Deserialize, Serialize)]
pub struct Decision {
    pub decision: String,
    pub reason: String,
    pub risk: i32,
}

impl Decision {
    pub fn is_approve(&self) -> bool {
        self.decision == "APPROVE"
    }
}

/// Build the tool schema as a serde_json::Value.
fn tool_schema() -> serde_json::Value {
    serde_json::json!({
        "type": "object",
        "properties": {
            "decision": {
                "type": "string",
                "enum": ["APPROVE", "DENY"],
                "description": "Whether to allow the command to execute."
            },
            "reason": {
                "type": "string",
                "description": "Brief explanation for the decision."
            },
            "risk": {
                "type": "integer",
                "minimum": 0,
                "maximum": 10,
                "description": "Risk score 0-10. 0=harmless read, 5=moderate side effects, 10=catastrophic/irreversible."
            }
        },
        "required": ["decision", "reason", "risk"]
    })
}

/// Call the LLM to evaluate a command, returning a parsed Decision.
pub async fn call_llm(
    config: &Config,
    system_prompt: &str,
    command: &str,
    host: &str,
) -> Result<Decision> {
    let user_message = format!("Host: {}\nCommand: {}", host, command);
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(config.timeout))
        .build()?;

    let raw_json = match config.api_type {
        ApiType::Anthropic => call_anthropic(&client, config, system_prompt, &user_message).await?,
        ApiType::OpenAI => call_openai(&client, config, system_prompt, &user_message).await?,
    };

    parse_decision(&raw_json)
}

async fn call_anthropic(
    client: &reqwest::Client,
    config: &Config,
    system_prompt: &str,
    user_message: &str,
) -> Result<String> {
    let body = serde_json::json!({
        "model": config.model,
        "max_tokens": config.max_tokens,
        "system": system_prompt,
        "tool_choice": {"type": "tool", "name": TOOL_NAME},
        "tools": [{
            "name": TOOL_NAME,
            "description": TOOL_DESC,
            "input_schema": tool_schema()
        }],
        "messages": [{"role": "user", "content": user_message}]
    });

    tracing::debug!("Anthropic request to {}", config.api_url);
    tracing::trace!("Request body: {}", serde_json::to_string_pretty(&body)?);

    let response = client
        .post(&config.api_url)
        .header("x-api-key", &config.api_key)
        .header("anthropic-version", "2023-06-01")
        .header("content-type", "application/json")
        .json(&body)
        .send()
        .await?;

    let status = response.status();
    let response_text = response.text().await?;

    tracing::debug!("Anthropic response status: {}", status);
    tracing::trace!("Response body: {}", response_text);

    if !status.is_success() {
        bail!("Anthropic API error ({}): {}", status, response_text);
    }

    let parsed: serde_json::Value = serde_json::from_str(&response_text)?;

    // Extract tool_use input from content array
    if let Some(content) = parsed.get("content").and_then(|c| c.as_array()) {
        for block in content {
            if block.get("type").and_then(|t| t.as_str()) == Some("tool_use") {
                if let Some(input) = block.get("input") {
                    return Ok(input.to_string());
                }
            }
        }
    }

    // Check for API error
    if let Some(err) = parsed.get("error").and_then(|e| e.get("message")) {
        bail!("Anthropic API error: {}", err);
    }

    bail!(
        "Failed to extract tool_use from Anthropic response: {}",
        response_text
    );
}

async fn call_openai(
    client: &reqwest::Client,
    config: &Config,
    system_prompt: &str,
    user_message: &str,
) -> Result<String> {
    let body = serde_json::json!({
        "model": config.model,
        "max_tokens": config.max_tokens,
        "tool_choice": {"type": "function", "function": {"name": TOOL_NAME}},
        "tools": [{
            "type": "function",
            "function": {
                "name": TOOL_NAME,
                "description": TOOL_DESC,
                "parameters": tool_schema()
            }
        }],
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_message}
        ]
    });

    tracing::debug!("OpenAI request to {}", config.api_url);
    tracing::trace!("Request body: {}", serde_json::to_string_pretty(&body)?);

    let response = client
        .post(&config.api_url)
        .header("Authorization", format!("Bearer {}", config.api_key))
        .header("content-type", "application/json")
        .json(&body)
        .send()
        .await?;

    let status = response.status();
    let response_text = response.text().await?;

    tracing::debug!("OpenAI response status: {}", status);
    tracing::trace!("Response body: {}", response_text);

    if !status.is_success() {
        bail!("OpenAI API error ({}): {}", status, response_text);
    }

    let parsed: serde_json::Value = serde_json::from_str(&response_text)?;

    // Extract function arguments from tool_calls
    if let Some(args) = parsed
        .pointer("/choices/0/message/tool_calls/0/function/arguments")
        .and_then(|v| v.as_str())
    {
        return Ok(args.to_string());
    }

    // Check for API error
    if let Some(err) = parsed.get("error").and_then(|e| e.get("message")) {
        bail!("OpenAI API error: {}", err);
    }

    bail!(
        "Failed to extract function arguments from OpenAI response: {}",
        response_text
    );
}

/// Parse the LLM's JSON output into a Decision, with fallback parsing.
fn parse_decision(json_str: &str) -> Result<Decision> {
    // Try direct parse first
    if let Ok(decision) = serde_json::from_str::<Decision>(json_str) {
        return Ok(decision);
    }

    // Fallback: try to extract JSON object from freeform text
    if let Some(start) = json_str.find('{') {
        if let Some(end) = json_str[start..].find('}') {
            let candidate = &json_str[start..=start + end];
            if let Ok(decision) = serde_json::from_str::<Decision>(candidate) {
                return Ok(decision);
            }
        }
    }

    // If we can't parse at all, fail closed (DENY)
    tracing::warn!(
        "Failed to parse LLM response, defaulting to DENY: {}",
        json_str
    );
    Ok(Decision {
        decision: "DENY".to_string(),
        reason: "Failed to parse LLM response".to_string(),
        risk: 5,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_decision_valid() {
        let json = r#"{"decision": "APPROVE", "reason": "read-only command", "risk": 1}"#;
        let d = parse_decision(json).unwrap();
        assert!(d.is_approve());
        assert_eq!(d.risk, 1);
        assert_eq!(d.reason, "read-only command");
    }

    #[test]
    fn test_parse_decision_deny() {
        let json = r#"{"decision": "DENY", "reason": "destructive command", "risk": 9}"#;
        let d = parse_decision(json).unwrap();
        assert!(!d.is_approve());
        assert_eq!(d.risk, 9);
    }

    #[test]
    fn test_parse_decision_embedded_json() {
        let json = r#"Here is my analysis: {"decision": "DENY", "reason": "bad", "risk": 7} done"#;
        let d = parse_decision(json).unwrap();
        assert!(!d.is_approve());
        assert_eq!(d.risk, 7);
    }

    #[test]
    fn test_parse_decision_garbage() {
        let json = "this is not json at all";
        let d = parse_decision(json).unwrap();
        assert!(!d.is_approve()); // fail closed
        assert_eq!(d.decision, "DENY");
    }

    #[test]
    fn test_tool_schema_has_required_fields() {
        let schema = tool_schema();
        let required = schema["required"].as_array().unwrap();
        assert!(required.contains(&serde_json::json!("decision")));
        assert!(required.contains(&serde_json::json!("reason")));
        assert!(required.contains(&serde_json::json!("risk")));
    }
}
