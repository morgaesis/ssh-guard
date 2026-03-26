use crate::{redact::redact_output, validate::ResponseValidator};
use anyhow::Result;
use futures::{Stream, StreamExt};
use serde::{Deserialize, Serialize};
use std::pin::Pin;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamChunk {
    pub content: String,
    pub finish_reason: Option<String>,
}

pub struct StreamProcessor {
    validator: Option<ResponseValidator>,
    buffer: String,
    chunk_size: usize,
}

impl StreamProcessor {
    pub fn new(validator: Option<ResponseValidator>) -> Self {
        Self {
            validator,
            buffer: String::new(),
            chunk_size: 1024, // Default chunk size
        }
    }

    pub fn with_chunk_size(mut self, size: usize) -> Self {
        self.chunk_size = size;
        self
    }

    pub async fn process_stream<S>(
        &mut self,
        input: S,
    ) -> Pin<Box<dyn Stream<Item = Result<StreamChunk>> + Send>>
    where
        S: Stream<Item = Result<StreamChunk>> + Send + 'static,
    {
        let (tx, rx) = mpsc::channel(32);
        let chunk_size = self.chunk_size;
        let validator = self.validator.clone();

        tokio::spawn(async move {
            let mut context_buffer = String::new();
            let mut pending_buffer = String::new();

            futures::pin_mut!(input);

            while let Some(chunk_result) = input.next().await {
                match chunk_result {
                    Ok(chunk) => {
                        // Add new content to the context buffer
                        context_buffer.push_str(&chunk.content);
                        pending_buffer.push_str(&chunk.content);

                        // Process complete chunks from the pending buffer
                        while pending_buffer.len() >= chunk_size {
                            let chunk_content = pending_buffer.drain(..chunk_size).collect::<String>();

                            // Apply redaction and validation
                            let processed_content = if let Some(validator) = &validator {
                                let response = crate::provider::ModelResponse {
                                    content: chunk_content.clone(),
                                    model: String::new(),
                                    usage: None,
                                };

                                match validator.validate_response(&response) {
                                    Ok(result) => {
                                        if result.has_modifications() {
                                            result.modified_content.unwrap_or(chunk_content)
                                        } else {
                                            chunk_content
                                        }
                                    }
                                    Err(_) => chunk_content,
                                }
                            } else {
                                redact_output(&chunk_content)
                            };

                            let _ = tx.send(Ok(StreamChunk {
                                content: processed_content,
                                finish_reason: None,
                            })).await;
                        }

                        // If this is the final chunk, process any remaining content
                        if chunk.finish_reason.is_some() {
                            if !pending_buffer.is_empty() {
                                let final_content = if let Some(validator) = &validator {
                                    let response = crate::provider::ModelResponse {
                                        content: pending_buffer.clone(),
                                        model: String::new(),
                                        usage: None,
                                    };

                                    match validator.validate_response(&response) {
                                        Ok(result) => {
                                            if result.has_modifications() {
                                                result.modified_content.unwrap_or(pending_buffer.clone())
                                            } else {
                                                pending_buffer.clone()
                                            }
                                        }
                                        Err(_) => pending_buffer.clone(),
                                    }
                                } else {
                                    redact_output(&pending_buffer)
                                };

                                let _ = tx.send(Ok(StreamChunk {
                                    content: final_content,
                                    finish_reason: chunk.finish_reason.clone(),
                                })).await;
                            }
                        }
                    }
                    Err(e) => {
                        let _ = tx.send(Err(e)).await;
                        break;
                    }
                }
            }
        });

        Box::pin(ReceiverStream::new(rx))
    }
}

#[derive(Clone)]
pub struct StreamingConfig {
    pub chunk_size: usize,
    pub max_context_size: usize,
    pub sliding_window_size: usize,
}

impl Default for StreamingConfig {
    fn default() -> Self {
        Self {
            chunk_size: 1024,
            max_context_size: 32768,
            sliding_window_size: 4096,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::stream;
    use tokio_stream::StreamExt;

    #[tokio::test]
    async fn test_stream_processing() {
        let processor = StreamProcessor::new(None).with_chunk_size(10);

        let input_chunks = vec![
            Ok(StreamChunk {
                content: "This is a secret: password123".to_string(),
                finish_reason: None,
            }),
            Ok(StreamChunk {
                content: " and API_KEY=abc123".to_string(),
                finish_reason: Some("stop".to_string()),
            }),
        ];

        let mut processed = processor
            .process_stream(stream::iter(input_chunks))
            .await;

        while let Some(result) = processed.next().await {
            match result {
                Ok(chunk) => {
                    assert!(!chunk.content.contains("password123"));
                    assert!(!chunk.content.contains("abc123"));
                    assert!(chunk.content.contains("[REDACTED]"));
                }
                Err(e) => panic!("Stream processing error: {}", e),
            }
        }
    }

    #[tokio::test]
    async fn test_stream_validation() {
        use crate::validate::{ValidationConfig, ContentFilter, FilterAction};

        let config = ValidationConfig {
            max_response_length: 1000,
            allowed_html_tags: vec![],
            blocked_patterns: vec![],
            content_filters: vec![
                ContentFilter {
                    name: "sensitive".to_string(),
                    pattern: r"(?i)password|secret|key".to_string(),
                    action: FilterAction::Redact,
                },
            ],
        };

        let validator = ResponseValidator::new(config).unwrap();
        let processor = StreamProcessor::new(Some(validator)).with_chunk_size(10);

        let input_chunks = vec![
            Ok(StreamChunk {
                content: "The password is: secret123".to_string(),
                finish_reason: None,
            }),
        ];

        let mut processed = processor
            .process_stream(stream::iter(input_chunks))
            .await;

        while let Some(result) = processed.next().await {
            match result {
                Ok(chunk) => {
                    assert!(!chunk.content.contains("password"));
                    assert!(!chunk.content.contains("secret123"));
                    assert!(chunk.content.contains("[REDACTED]"));
                }
                Err(e) => panic!("Stream processing error: {}", e),
            }
        }
    }

    #[tokio::test]
    async fn test_stream_chunk_boundaries() {
        let processor = StreamProcessor::new(None).with_chunk_size(5);

        let input_chunks = vec![
            Ok(StreamChunk {
                content: "pass".to_string(),
                finish_reason: None,
            }),
            Ok(StreamChunk {
                content: "word123".to_string(),
                finish_reason: Some("stop".to_string()),
            }),
        ];

        let mut processed = processor
            .process_stream(stream::iter(input_chunks))
            .await;

        let mut processed_content = String::new();
        while let Some(result) = processed.next().await {
            match result {
                Ok(chunk) => {
                    processed_content.push_str(&chunk.content);
                }
                Err(e) => panic!("Stream processing error: {}", e),
            }
        }

        assert!(!processed_content.contains("password123"));
        assert!(processed_content.contains("[REDACTED]"));
    }
}