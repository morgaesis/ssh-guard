use crate::provider::ModelResponse;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationConfig {
    pub max_response_length: usize,
    pub allowed_html_tags: Vec<String>,
    pub blocked_patterns: Vec<String>,
    pub content_filters: Vec<ContentFilter>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContentFilter {
    pub name: String,
    pub pattern: String,
    pub action: FilterAction,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FilterAction {
    Block,
    Redact,
    Warn,
}

pub struct ResponseValidator {
    config: ValidationConfig,
    cached_regexes: HashMap<String, regex::Regex>,
}

impl ResponseValidator {
    pub fn new(config: ValidationConfig) -> Result<Self> {
        let mut cached_regexes = HashMap::new();

        // Pre-compile all regex patterns
        for filter in &config.content_filters {
            let regex = regex::Regex::new(&filter.pattern)?;
            cached_regexes.insert(filter.name.clone(), regex);
        }

        for pattern in &config.blocked_patterns {
            let regex = regex::Regex::new(pattern)?;
            cached_regexes.insert(pattern.clone(), regex);
        }

        Ok(Self {
            config,
            cached_regexes,
        })
    }

    pub fn validate_response(&self, response: &ModelResponse) -> Result<ValidationResult> {
        let mut result = ValidationResult::default();

        // Check response length
        if response.content.len() > self.config.max_response_length {
            result.issues.push(ValidationIssue::ResponseTooLong {
                length: response.content.len(),
                max_length: self.config.max_response_length,
            });
        }

        // Check for blocked patterns
        for pattern in &self.config.blocked_patterns {
            if let Some(regex) = self.cached_regexes.get(pattern) {
                if regex.is_match(&response.content) {
                    result.issues.push(ValidationIssue::BlockedPattern {
                        pattern: pattern.clone(),
                    });
                }
            }
        }

        // Apply content filters
        for filter in &self.config.content_filters {
            if let Some(regex) = self.cached_regexes.get(&filter.name) {
                if regex.is_match(&response.content) {
                    match filter.action {
                        FilterAction::Block => {
                            result.issues.push(ValidationIssue::ContentFilter {
                                filter: filter.name.clone(),
                                action: filter.action.clone(),
                            });
                        }
                        FilterAction::Redact => {
                            result.modified_content = Some(
                                regex.replace_all(&response.content, "[REDACTED]").to_string(),
                            );
                        }
                        FilterAction::Warn => {
                            result.warnings.push(format!(
                                "Content matched filter: {}",
                                filter.name
                            ));
                        }
                    }
                }
            }
        }

        // Sanitize HTML if present
        if response.content.contains('<') {
            result.modified_content = Some(self.sanitize_html(&response.content));
        }

        Ok(result)
    }

    fn sanitize_html(&self, content: &str) -> String {
        use ammonia::Builder;

        let mut builder = Builder::new();
        builder.tags(self.config.allowed_html_tags.iter().map(|s| s.as_str()));
        builder.clean(content).to_string()
    }
}

#[derive(Debug, Default)]
pub struct ValidationResult {
    pub issues: Vec<ValidationIssue>,
    pub warnings: Vec<String>,
    pub modified_content: Option<String>,
}

impl ValidationResult {
    pub fn is_valid(&self) -> bool {
        self.issues.is_empty()
    }

    pub fn has_modifications(&self) -> bool {
        self.modified_content.is_some()
    }
}

#[derive(Debug)]
pub enum ValidationIssue {
    ResponseTooLong {
        length: usize,
        max_length: usize,
    },
    BlockedPattern {
        pattern: String,
    },
    ContentFilter {
        filter: String,
        action: FilterAction,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_config() -> ValidationConfig {
        ValidationConfig {
            max_response_length: 1000,
            allowed_html_tags: vec!["b".to_string(), "i".to_string()],
            blocked_patterns: vec![r"(?i)password:\s*\w+".to_string()],
            content_filters: vec![
                ContentFilter {
                    name: "profanity".to_string(),
                    pattern: r"(?i)bad|word".to_string(),
                    action: FilterAction::Redact,
                },
                ContentFilter {
                    name: "pii".to_string(),
                    pattern: r"\b\d{3}-\d{2}-\d{4}\b".to_string(),
                    action: FilterAction::Block,
                },
            ],
        }
    }

    #[test]
    fn test_response_length_validation() {
        let config = create_test_config();
        let validator = ResponseValidator::new(config).unwrap();

        let response = ModelResponse {
            content: "a".repeat(2000),
            model: "test".to_string(),
            usage: None,
        };

        let result = validator.validate_response(&response).unwrap();
        assert!(!result.is_valid());
        assert!(matches!(
            result.issues[0],
            ValidationIssue::ResponseTooLong { .. }
        ));
    }

    #[test]
    fn test_blocked_pattern_validation() {
        let config = create_test_config();
        let validator = ResponseValidator::new(config).unwrap();

        let response = ModelResponse {
            content: "The password: secret123 should be blocked".to_string(),
            model: "test".to_string(),
            usage: None,
        };

        let result = validator.validate_response(&response).unwrap();
        assert!(!result.is_valid());
        assert!(matches!(
            result.issues[0],
            ValidationIssue::BlockedPattern { .. }
        ));
    }

    #[test]
    fn test_content_filter_redaction() {
        let config = create_test_config();
        let validator = ResponseValidator::new(config).unwrap();

        let response = ModelResponse {
            content: "This has a bad word in it".to_string(),
            model: "test".to_string(),
            usage: None,
        };

        let result = validator.validate_response(&response).unwrap();
        assert!(result.is_valid()); // Redaction doesn't make it invalid
        assert!(result.has_modifications());
        assert!(result
            .modified_content
            .unwrap()
            .contains("[REDACTED]"));
    }

    #[test]
    fn test_html_sanitization() {
        let config = create_test_config();
        let validator = ResponseValidator::new(config).unwrap();

        let response = ModelResponse {
            content: "This has <b>bold</b> and <script>alert('xss')</script>".to_string(),
            model: "test".to_string(),
            usage: None,
        };

        let result = validator.validate_response(&response).unwrap();
        assert!(result.has_modifications());
        let sanitized = result.modified_content.unwrap();
        assert!(sanitized.contains("<b>bold</b>"));
        assert!(!sanitized.contains("<script>"));
    }
}