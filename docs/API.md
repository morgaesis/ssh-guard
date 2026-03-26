# Model Guard API Documentation

## Overview

Model Guard provides a secure, efficient, and feature-rich interface for interacting with various language models. It includes built-in security features, response validation, cost optimization, and comprehensive monitoring.

## Getting Started

### Installation

Add Model Guard to your Cargo.toml:

```toml
[dependencies]
ssh-guard = { git = "https://github.com/morgaesis/ssh-guard" }
```

### Basic Usage

```rust
use ssh_guard::sdk::{ModelGuardClient, ClientConfig, ProviderConfig};

#[tokio::main]
async fn main() -> Result<()> {
    // Configure the client
    let config = ClientConfig {
        providers: vec![
            ProviderConfig {
                name: "openai".to_string(),
                api_key: "your-api-key".to_string(),
                endpoint: None,
            }
        ],
        cache_enabled: true,
        validation_enabled: true,
        optimization_enabled: true,
        metrics_enabled: true,
    };

    // Create client instance
    let client = ModelGuardClient::new(config).await?;

    // Send a message
    let response = client
        .send_message("Tell me a joke", "gpt-4")
        .await?;

    println!("Response: {}", response.content);
    Ok(())
}
```

## Core Components

### Client Configuration

The `ClientConfig` struct allows you to configure various aspects of the Model Guard client:

```rust
pub struct ClientConfig {
    pub providers: Vec<ProviderConfig>,
    pub cache_enabled: bool,
    pub validation_enabled: bool,
    pub optimization_enabled: bool,
    pub metrics_enabled: bool,
}
```

### Provider Configuration

Each provider requires specific configuration:

```rust
pub struct ProviderConfig {
    pub name: String,
    pub api_key: String,
    pub endpoint: Option<String>,
}
```

### Making Requests

The client provides several methods for interacting with models:

1. Basic message sending:
```rust
async fn send_message(&self, content: &str, model: &str) -> Result<ModelResponse>
```

2. Advanced request processing:
```rust
async fn process_request(&self, request: ModelRequest) -> Result<ModelResponse>
```

3. Streaming responses:
```rust
async fn send_streaming_message(
    &self,
    content: &str,
    model: &str,
) -> Result<impl Stream<Item = Result<String>>>
```

## Features

### Caching

When enabled, Model Guard automatically caches responses to identical requests:

```rust
// Configure caching
let config = ClientConfig {
    cache_enabled: true,
    ..Default::default()
};

// Cache is automatically used for identical requests
let response1 = client.send_message("Hello", "gpt-4").await?;
let response2 = client.send_message("Hello", "gpt-4").await?; // Uses cache
```

### Response Validation

Model Guard can validate responses against custom rules:

```rust
// Enable validation
let config = ClientConfig {
    validation_enabled: true,
    ..Default::default()
};

// Validation happens automatically for each response
let response = client.send_message("Hello", "gpt-4").await?;
```

### Cost Optimization

The optimizer automatically selects the most cost-effective model:

```rust
// Enable optimization
let config = ClientConfig {
    optimization_enabled: true,
    ..Default::default()
};

// Use "auto" to let the optimizer choose the model
let response = client.send_message("Hello", "auto").await?;
```

### Metrics Collection

Track usage and performance metrics:

```rust
// Enable metrics
let config = ClientConfig {
    metrics_enabled: true,
    ..Default::default()
};

// Get metrics
let metrics = client.get_metrics().await;
```

## Security Features

1. Credential Protection:
   - API keys and credentials are never exposed in responses
   - Automatic redaction of sensitive information
   - Secure credential storage integration

2. Request Validation:
   - Input sanitization
   - Content safety checks
   - Rate limiting

3. Response Safety:
   - Content filtering
   - Code execution prevention
   - Schema validation

## Error Handling

Model Guard provides detailed error types:

```rust
#[derive(Debug)]
pub enum ModelGuardError {
    RequestError(String),
    ValidationError(Vec<ValidationIssue>),
    ProviderError(String),
    ConfigurationError(String),
}
```

## Best Practices

1. Enable all security features in production:
```rust
let config = ClientConfig {
    cache_enabled: true,
    validation_enabled: true,
    optimization_enabled: true,
    metrics_enabled: true,
    ..Default::default()
};
```

2. Use streaming for long responses:
```rust
let mut stream = client
    .send_streaming_message("Generate a long story", "gpt-4")
    .await?;

while let Some(chunk) = stream.next().await {
    print!("{}", chunk?);
}
```

3. Implement proper error handling:
```rust
match client.send_message("Hello", "gpt-4").await {
    Ok(response) => println!("Success: {}", response.content),
    Err(e) => match e.downcast_ref::<ModelGuardError>() {
        Some(ModelGuardError::ValidationError(issues)) => {
            println!("Validation failed: {:?}", issues);
        }
        _ => println!("Error: {}", e),
    }
}
```

## Examples

### Basic Chat

```rust
let client = ModelGuardClient::new(config).await?;

let response = client
    .send_message("What is the capital of France?", "gpt-3.5-turbo")
    .await?;

println!("Answer: {}", response.content);
```

### Streaming Chat

```rust
let mut stream = client
    .send_streaming_message("Write a story about a dragon", "gpt-4")
    .await?;

while let Some(chunk) = stream.next().await {
    match chunk {
        Ok(content) => print!("{}", content),
        Err(e) => eprintln!("Stream error: {}", e),
    }
}
```

### Using Cost Optimization

```rust
let response = client
    .process_request(ModelRequest {
        model: "auto".to_string(),
        messages: vec![Message {
            role: "user".to_string(),
            content: "Explain quantum computing".to_string(),
        }],
        temperature: Some(0.7),
        max_tokens: Some(1000),
        stream: None,
    })
    .await?;
```

## Contributing

See our [CONTRIBUTING.md](../CONTRIBUTING.md) for guidelines on contributing to Model Guard.