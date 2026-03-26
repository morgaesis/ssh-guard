use crate::provider::ModelResponse;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, sync::Arc};
use tokio::sync::RwLock;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationRule {
    pub name: String,
    pub rule_type: RuleType,
    pub parameters: HashMap<String, String>,
    pub severity: Severity,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RuleType {
    Length {
        min: Option<usize>,
        max: Option<usize>,
    },
    Format {
        pattern: String,
    },
    Schema {
        schema: serde_json::Value,
    },
    Classifier {
        model: String,
        threshold: f32,
    },
    Custom {
        validator_fn: String,
    },
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum Severity {
    Error,
    Warning,
    Info,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationIssue {
    pub rule_name: String,
    pub severity: Severity,
    pub message: String,
    pub context: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Default)]
pub struct ValidationResult {
    pub issues: Vec<ValidationIssue>,
    pub score: f32,
    pub metadata: HashMap<String, String>,
}

impl ValidationResult {
    pub fn has_errors(&self) -> bool {
        self.issues
            .iter()
            .any(|issue| issue.severity == Severity::Error)
    }

    pub fn has_warnings(&self) -> bool {
        self.issues
            .iter()
            .any(|issue| issue.severity == Severity::Warning)
    }
}

pub struct ResponseValidator {
    rules: Arc<RwLock<Vec<ValidationRule>>>,
    custom_validators: Arc<RwLock<HashMap<String, Box<dyn CustomValidator>>>>,
}

#[async_trait::async_trait]
pub trait CustomValidator: Send + Sync {
    async fn validate(&self, response: &ModelResponse) -> Result<ValidationResult>;
}

impl ResponseValidator {
    pub fn new() -> Self {
        Self {
            rules: Arc::new(RwLock::new(Vec::new())),
            custom_validators: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn add_rule(&self, rule: ValidationRule) {
        let mut rules = self.rules.write().await;
        rules.push(rule);
    }

    pub async fn register_custom_validator(
        &self,
        name: String,
        validator: Box<dyn CustomValidator>,
    ) {
        let mut validators = self.custom_validators.write().await;
        validators.insert(name, validator);
    }

    pub async fn validate(&self, response: &ModelResponse) -> Result<ValidationResult> {
        let mut result = ValidationResult::default();
        let rules = self.rules.read().await;

        for rule in rules.iter() {
            match &rule.rule_type {
                RuleType::Length { min, max } => {
                    self.validate_length(&response.content, min, max, rule, &mut result)?;
                }
                RuleType::Format { pattern } => {
                    self.validate_format(&response.content, pattern, rule, &mut result)?;
                }
                RuleType::Schema { schema } => {
                    self.validate_schema(&response.content, schema, rule, &mut result)?;
                }
                RuleType::Classifier { model, threshold } => {
                    self.validate_with_classifier(&response.content, model, *threshold, rule, &mut result)
                        .await?;
                }
                RuleType::Custom { validator_fn } => {
                    self.validate_custom(response, validator_fn, rule, &mut result)
                        .await?;
                }
            }
        }

        // Calculate overall score based on issue severity
        let total_issues = result.issues.len() as f32;
        if total_issues > 0.0 {
            let weighted_sum: f32 = result.issues.iter().map(|i| match i.severity {
                Severity::Error => 1.0,
                Severity::Warning => 0.5,
                Severity::Info => 0.1,
            }).sum();
            result.score = 1.0 - (weighted_sum / total_issues);
        } else {
            result.score = 1.0;
        }

        Ok(result)
    }

    fn validate_length(
        &self,
        content: &str,
        min: &Option<usize>,
        max: &Option<usize>,
        rule: &ValidationRule,
        result: &mut ValidationResult,
    ) -> Result<()> {
        let len = content.len();

        if let Some(min_len) = min {
            if len < *min_len {
                result.issues.push(ValidationIssue {
                    rule_name: rule.name.clone(),
                    severity: rule.severity,
                    message: format!("Content length {} is below minimum {}", len, min_len),
                    context: Some(serde_json::json!({ "length": len, "min": min_len })),
                });
            }
        }

        if let Some(max_len) = max {
            if len > *max_len {
                result.issues.push(ValidationIssue {
                    rule_name: rule.name.clone(),
                    severity: rule.severity,
                    message: format!("Content length {} exceeds maximum {}", len, max_len),
                    context: Some(serde_json::json!({ "length": len, "max": max_len })),
                });
            }
        }

        Ok(())
    }

    fn validate_format(
        &self,
        content: &str,
        pattern: &str,
        rule: &ValidationRule,
        result: &mut ValidationResult,
    ) -> Result<()> {
        let regex = regex::Regex::new(pattern)?;
        if !regex.is_match(content) {
            result.issues.push(ValidationIssue {
                rule_name: rule.name.clone(),
                severity: rule.severity,
                message: format!("Content does not match required format: {}", pattern),
                context: Some(serde_json::json!({ "pattern": pattern })),
            });
        }
        Ok(())
    }

    fn validate_schema(
        &self,
        content: &str,
        schema: &serde_json::Value,
        rule: &ValidationRule,
        result: &mut ValidationResult,
    ) -> Result<()> {
        let content_json: serde_json::Value = serde_json::from_str(content)
            .map_err(|e| anyhow::anyhow!("Invalid JSON content: {}", e))?;

        let schema: jsonschema::JSONSchema = jsonschema::JSONSchema::compile(schema)
            .map_err(|e| anyhow::anyhow!("Invalid JSON schema: {}", e))?;

        if let Err(errors) = schema.validate(&content_json) {
            for error in errors {
                result.issues.push(ValidationIssue {
                    rule_name: rule.name.clone(),
                    severity: rule.severity,
                    message: error.to_string(),
                    context: Some(serde_json::json!({
                        "path": error.instance_path.to_string(),
                        "schema_path": error.schema_path.to_string(),
                    })),
                });
            }
        }

        Ok(())
    }

    async fn validate_with_classifier(
        &self,
        content: &str,
        model: &str,
        threshold: f32,
        rule: &ValidationRule,
        result: &mut ValidationResult,
    ) -> Result<()> {
        // This would typically call another model to classify the content
        // For now, we'll just implement a simple mock
        if content.contains("unsafe") || content.contains("error") {
            result.issues.push(ValidationIssue {
                rule_name: rule.name.clone(),
                severity: rule.severity,
                message: format!("Content classified as unsafe by model {}", model),
                context: Some(serde_json::json!({
                    "model": model,
                    "threshold": threshold,
                    "score": 0.8,
                })),
            });
        }
        Ok(())
    }

    async fn validate_custom(
        &self,
        response: &ModelResponse,
        validator_fn: &str,
        rule: &ValidationRule,
        result: &mut ValidationResult,
    ) -> Result<()> {
        let validators = self.custom_validators.read().await;
        if let Some(validator) = validators.get(validator_fn) {
            let custom_result = validator.validate(response).await?;
            result.issues.extend(custom_result.issues);
            result
                .metadata
                .extend(custom_result.metadata.into_iter());
        }
        Ok(())
    }
}

// Example custom validator implementation
pub struct CodeValidator {
    language_patterns: HashMap<String, regex::Regex>,
}

impl CodeValidator {
    pub fn new() -> Result<Self> {
        let mut patterns = HashMap::new();
        patterns.insert(
            "python".to_string(),
            regex::Regex::new(r"^def\s+\w+\s*\([^)]*\)\s*:")?
        );
        patterns.insert(
            "rust".to_string(),
            regex::Regex::new(r"^(pub\s+)?fn\s+\w+\s*<?")?
        );
        Ok(Self {
            language_patterns: patterns,
        })
    }
}

#[async_trait::async_trait]
impl CustomValidator for CodeValidator {
    async fn validate(&self, response: &ModelResponse) -> Result<ValidationResult> {
        let mut result = ValidationResult::default();

        // Check for common code patterns
        for (lang, pattern) in &self.language_patterns {
            if pattern.is_match(&response.content) {
                result.metadata.insert("contains_code".to_string(), "true".to_string());
                result.metadata.insert("language".to_string(), lang.clone());

                // Validate basic syntax
                if response.content.contains("{") && !response.content.contains("}") {
                    result.issues.push(ValidationIssue {
                        rule_name: "code_syntax".to_string(),
                        severity: Severity::Error,
                        message: "Unmatched curly brace in code".to_string(),
                        context: Some(serde_json::json!({ "language": lang })),
                    });
                }
            }
        }

        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_length_validation() {
        let validator = ResponseValidator::new();

        validator.add_rule(ValidationRule {
            name: "length_check".to_string(),
            rule_type: RuleType::Length {
                min: Some(10),
                max: Some(100),
            },
            parameters: HashMap::new(),
            severity: Severity::Error,
        }).await;

        let response = ModelResponse {
            content: "too short".to_string(),
            model: "test".to_string(),
            usage: None,
        };

        let result = validator.validate(&response).await.unwrap();
        assert!(result.has_errors());
        assert_eq!(result.issues[0].severity, Severity::Error);
    }

    #[tokio::test]
    async fn test_format_validation() {
        let validator = ResponseValidator::new();

        validator.add_rule(ValidationRule {
            name: "json_format".to_string(),
            rule_type: RuleType::Format {
                pattern: r"^\{.*\}$".to_string(),
            },
            parameters: HashMap::new(),
            severity: Severity::Error,
        }).await;

        let response = ModelResponse {
            content: "not json".to_string(),
            model: "test".to_string(),
            usage: None,
        };

        let result = validator.validate(&response).await.unwrap();
        assert!(result.has_errors());
    }

    #[tokio::test]
    async fn test_custom_validator() {
        let validator = ResponseValidator::new();
        let code_validator = CodeValidator::new().unwrap();

        validator.register_custom_validator(
            "code_validator".to_string(),
            Box::new(code_validator),
        ).await;

        validator.add_rule(ValidationRule {
            name: "code_check".to_string(),
            rule_type: RuleType::Custom {
                validator_fn: "code_validator".to_string(),
            },
            parameters: HashMap::new(),
            severity: Severity::Warning,
        }).await;

        let response = ModelResponse {
            content: "def function_with_error(:\n    pass".to_string(),
            model: "test".to_string(),
            usage: None,
        };

        let result = validator.validate(&response).await.unwrap();
        assert!(result.has_warnings());
        assert!(result.metadata.contains_key("contains_code"));
    }

    #[tokio::test]
    async fn test_validation_scoring() {
        let validator = ResponseValidator::new();

        // Add multiple rules
        validator.add_rule(ValidationRule {
            name: "error_rule".to_string(),
            rule_type: RuleType::Length {
                min: Some(100),
                max: None,
            },
            parameters: HashMap::new(),
            severity: Severity::Error,
        }).await;

        validator.add_rule(ValidationRule {
            name: "warning_rule".to_string(),
            rule_type: RuleType::Format {
                pattern: r"^\{.*\}$".to_string(),
            },
            parameters: HashMap::new(),
            severity: Severity::Warning,
        }).await;

        let response = ModelResponse {
            content: "short content".to_string(),
            model: "test".to_string(),
            usage: None,
        };

        let result = validator.validate(&response).await.unwrap();
        assert!(result.score < 1.0);
        assert!(result.score >= 0.0);
    }
}