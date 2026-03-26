//! LLM Proxy Server
//!
//! HTTP proxy that forwards requests to upstream LLM APIs while redacting
//! sensitive data from both requests and responses before they reach the
//! AI agent or are logged.
//!
//! # Usage
//!
//! ```bash
//! guard proxy --port 8080 --upstream https://api.openai.com/v1
//! ```
//!
//! Configure AI agents to use `http://localhost:8080` as their API endpoint.
//!
//! # Supported Endpoints
//!
//! - `POST /chat/completions`    — OpenAI chat completion API
//! - `POST /completions`         — OpenAI completion API
//! - `POST /v1/chat/completions` — OpenAI with /v1 prefix
//! - `POST /v1/completions`      — OpenAI with /v1 prefix
//!
//! # Security Model
//!
//! Auth headers (`Authorization`, `x-api-key`, etc.) are passed through to
//! the upstream unmodified. They are never logged. Request and response bodies
//! are redacted using configurable patterns before forwarding or logging.

use crate::redact::Redactor;
use anyhow::{Context, Result};
use bytes::Bytes;
use http_body_util::{combinators::BoxBody, BodyExt, Full};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tracing::{debug, error, info, warn};

/// OpenAI-compatible chat completions endpoint.
const PATH_CHAT_COMPLETIONS: &str = "/chat/completions";
/// OpenAI-compatible completions endpoint.
const PATH_COMPLETIONS: &str = "/completions";
/// Prefix variant (some providers use /v1/... paths).
const PATH_V1_CHAT_COMPLETIONS: &str = "/v1/chat/completions";
const PATH_V1_COMPLETIONS: &str = "/v1/completions";

/// Headers that carry credentials — forwarded but never logged.
const SENSITIVE_HEADERS: &[&str] = &[
    "authorization",
    "x-api-key",
    "x-auth-token",
    "api-key",
    "x-openai-api-key",
    "anthropic-api-key",
    "x-anthropic-api-key",
];

// ---------------------------------------------------------------------------
// Type aliases
// ---------------------------------------------------------------------------

/// The body type received from inbound requests (hyper's streaming body).
type IncomingBody = hyper::body::Incoming;

/// The body type used for outbound (response) bodies sent back to clients.
///
/// We use `Infallible` as the error type because our outbound bodies are
/// always `Full<Bytes>` — a static, pre-collected buffer that cannot produce
/// streaming I/O errors.
type OutboundBody = BoxBody<Bytes, std::convert::Infallible>;

// ---------------------------------------------------------------------------
// Shared proxy state
// ---------------------------------------------------------------------------

/// State shared across all request handlers.
pub struct ProxyState {
    /// Base URL of the upstream LLM API (e.g. `https://api.openai.com/v1`).
    upstream: reqwest::Url,
    /// HTTP client for upstream requests.
    client: hyper_util::client::legacy::Client<
        hyper_util::client::legacy::connect::HttpConnector,
        OutboundBody,
    >,
    /// Redactor applied to request and response bodies.
    redactor: Redactor,
}

impl ProxyState {
    /// Construct proxy state.
    ///
    /// `upstream` must be a valid URL. Trailing slashes are stripped.
    fn new(upstream: &str) -> Result<Self> {
        let upstream = {
            let mut url = reqwest::Url::parse(upstream)
                .with_context(|| format!("invalid upstream URL: {upstream}"))?;
            let path = url.path().trim_end_matches('/').to_string();
            url.set_path(&path);
            url
        };

        let client =
            hyper_util::client::legacy::Client::builder(
                hyper_util::rt::TokioExecutor::default(),
            )
            .pool_idle_timeout(std::time::Duration::from_secs(90))
            .build_http::<OutboundBody>();

        Ok(Self {
            upstream,
            client,
            redactor: Redactor::new(),
        })
    }

    /// Build the upstream URL for a given incoming path+query.
    fn upstream_url(&self, path_and_query: &str) -> reqwest::Url {
        self.upstream
            .join(path_and_query)
            .expect("url.join is infallible")
    }
}

// ---------------------------------------------------------------------------
// Request handling
// ---------------------------------------------------------------------------

/// Handle a single proxied request.
///
/// Extracts the body, optionally redacts it (for logging), forwards to the
/// upstream, then returns either a redacted non-streaming response or a
/// streaming response whose SSE events are individually redacted.
async fn handle_request(
    state: Arc<ProxyState>,
    req: Request<IncomingBody>,
) -> Result<Response<OutboundBody>> {
    let path = req.uri().path_and_query().map(|pq| pq.as_str()).unwrap_or("");
    let method = req.method().clone();

    debug!(%method, %path, "incoming proxy request");

    if method != Method::POST {
        return Ok(error_response(
            StatusCode::METHOD_NOT_ALLOWED,
            "Only POST is supported",
        ));
    }

    let response = match path {
        p if p == PATH_CHAT_COMPLETIONS
            || p == PATH_COMPLETIONS
            || p == PATH_V1_CHAT_COMPLETIONS
            || p == PATH_V1_COMPLETIONS => forward_request(state, req).await,
        _ => Ok(error_response(
            StatusCode::NOT_FOUND,
            "Unknown endpoint. Supported: /chat/completions, /completions",
        )),
    };

    if let Ok(resp) = &response {
        debug!(status = resp.status().as_u16(), "proxy response");
    } else if let Err(e) = &response {
        error!("proxy error: {}", e);
    }

    response
}

/// Forward a request to the upstream LLM API, redacting the body before
/// logging and redacting the response body before returning it to the client.
async fn forward_request(
    state: Arc<ProxyState>,
    req: Request<IncomingBody>,
) -> Result<Response<OutboundBody>> {
    let path = req.uri().path_and_query().map(|pq| pq.as_str()).unwrap_or("");
    let upstream_url = state.upstream_url(path).to_string();

    // Extract method and headers before consuming the body.
    let method = req.method().clone();
    let req_headers = req.headers().clone();

    // Collect the incoming body so we can inspect and forward it.
    let body_bytes = req.collect().await?.to_bytes();

    // Log the redacted request body for audit/debugging.
    let redacted_body =
        state.redactor.redact(String::from_utf8_lossy(&body_bytes).as_ref());
    debug!(body = %redacted_body, "request body (redacted)");

    // Check if this is a streaming request.
    let is_streaming = detect_streaming(&body_bytes);
    let _ = is_streaming; // reserved for future per-chunk streaming

    // Build the upstream request, copying headers (hop-by-hop headers are
    // stripped by hyper automatically).
    let mut upstream_req = Request::builder()
        .method(method)
        .uri(&upstream_url);

    for (name, value) in req_headers.iter() {
        let name_lower = name.as_str().to_lowercase();
        upstream_req = upstream_req.header(name.as_str(), value.as_bytes());
        if SENSITIVE_HEADERS.contains(&name_lower.as_str()) {
            debug!(header = %name_lower, "forwarding sensitive header");
        }
    }

    // Build a `Full<Bytes>` body boxed to `OutboundBody`.
    let upstream_body: OutboundBody = Full::new(body_bytes.clone()).boxed();

    let upstream_req = upstream_req
        .body(upstream_body)
        .context("failed to build upstream request")?;

    // Send the request upstream.
    let upstream_resp = state
        .client
        .request(upstream_req)
        .await
        .context("upstream request failed")?;

    // Extract status and headers before consuming the body.
    let status = upstream_resp.status();
    let resp_headers: hyper::header::HeaderMap = upstream_resp
        .headers()
        .iter()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();

    // Non-streaming response: redact the full body.
    if !is_sse_content_type(&resp_headers) {
        let body_bytes = upstream_resp.collect().await?.to_bytes();
        let redacted_body =
            state.redactor.redact(String::from_utf8_lossy(&body_bytes).as_ref());
        debug!(body = %redacted_body, "response body (redacted)");

        let mut resp = Response::builder().status(status);
        for (name, value) in resp_headers.iter() {
            resp = resp.header(name.as_str(), value.as_bytes());
        }
        let body: OutboundBody = Full::new(body_bytes).boxed();
        return Ok(resp.body(body)?);
    }

    // SSE/streaming response: collect all chunks, redact each NDJSON event.
    info!(%status, "streaming response from upstream");
    let body_bytes = upstream_resp.collect().await?.to_bytes();
    let processed = redact_sse_ndjson(&state.redactor, &body_bytes);
    let body: OutboundBody = Full::new(processed).boxed();
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "text/event-stream; charset=utf-8")
        .header("cache-control", "no-cache")
        .header("connection", "keep-alive")
        .body(body)?)
}

// ---------------------------------------------------------------------------
// SSE / NDJSON streaming
// ---------------------------------------------------------------------------

/// Returns true when the request body contains `"stream": true` or `"stream": 1`.
fn detect_streaming(body: &[u8]) -> bool {
    if let Ok(text) = std::str::from_utf8(body) {
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(text) {
            if let Some(val) = json
                .get("stream")
                .and_then(|v| v.as_bool())
                .or_else(|| json.get("stream").and_then(|v| v.as_i64()).map(|n| n != 0))
            {
                return val;
            }
        }
    }
    false
}

/// Returns true when the Content-Type header indicates SSE or NDJSON.
fn is_sse_content_type(headers: &hyper::header::HeaderMap) -> bool {
    headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .map(|ct| {
            ct.contains("text/event-stream") || ct.contains("application/x-ndjson")
        })
        .unwrap_or(false)
}

/// Redact secrets from a buffer containing NDJSON SSE data.
///
/// Each line starting with `data: ` is parsed as JSON; content fields are
/// redacted in-place. Other lines (blank lines, `data: [DONE]`, etc.) are
/// passed through unchanged.
fn redact_sse_ndjson(redactor: &Redactor, input: &[u8]) -> Bytes {
    let text = String::from_utf8_lossy(input);
    let mut output = String::with_capacity(input.len());

    for line in text.lines() {
        let trimmed = line.trim();

        if let Some(event_payload) = trimmed.strip_prefix("data: ") {
            let processed = redact_sse_event(redactor, event_payload);
            output.push_str("data: ");
            output.push_str(&processed);
        } else {
            // Pass through comments, blank lines, and any other content.
            output.push_str(line);
        }
        output.push('\n');
    }

    if !output.is_empty() && !output.ends_with('\n') {
        output.push('\n');
    }

    Bytes::from(output)
}

/// Redact a single SSE event payload (the JSON after `data: `).
///
/// Handles both OpenAI chat completion chunks (`delta.content`) and legacy
/// completion chunks (`text`). Unknown event shapes are passed through
/// unchanged; plain-text non-JSON events have the full string redacted.
fn redact_sse_event(redactor: &Redactor, event: &str) -> String {
    if event == "[DONE]" {
        return event.to_string();
    }

    if let Ok(json) = serde_json::from_str::<serde_json::Value>(event) {
        let modified = redact_json_content(redactor, json);
        serde_json::to_string(&modified).unwrap_or_else(|_| event.to_string())
    } else {
        redactor.redact(event)
    }
}

/// Walk a parsed JSON value and redact string content fields that may contain
/// LLM-generated secrets.
fn redact_json_content(redactor: &Redactor, mut json: serde_json::Value) -> serde_json::Value {
    // OpenAI chat completion: choices[].delta.content
    if let Some(choices) = json.get_mut("choices").and_then(|c| c.as_array_mut()) {
        for choice in choices {
            if let Some(delta) = choice.get_mut("delta").and_then(|d| d.as_object_mut()) {
                if let Some(content) = delta.get("content").and_then(|c| c.as_str()) {
                    let redacted = redactor.redact(content);
                    if redacted != content {
                        delta.insert(
                            "content".to_string(),
                            serde_json::Value::String(redacted),
                        );
                    }
                }
            }
            // Legacy completion: choices[].text
            if let Some(text_str) = choice.get("text").and_then(|t| t.as_str()) {
                let redacted = redactor.redact(text_str);
                if redacted != text_str {
                    if let Some(obj) = choice.as_object_mut() {
                        obj.insert("text".to_string(), serde_json::Value::String(redacted));
                    }
                }
            }
        }
    }
    json
}

// ---------------------------------------------------------------------------
// Error responses
// ---------------------------------------------------------------------------

/// Build a JSON error response with the given status code and message.
fn error_response(status: StatusCode, message: &str) -> Response<OutboundBody> {
    let body = serde_json::json!({
        "error": { "message": message, "type": "proxy_error" }
    });
    let body: OutboundBody = Full::new(Bytes::from(body.to_string())).boxed();

    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(body)
        .expect("error response builder is valid")
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Start the LLM proxy server.
///
/// `port`     — TCP port to listen on (binds to 127.0.0.1).
/// `upstream` — Base URL of the upstream LLM API
///              (e.g. `https://api.openai.com/v1`).
///
/// The function runs until the process is interrupted or a fatal error occurs.
pub async fn start_proxy(port: u16, upstream: &str) -> Result<()> {
    let state = Arc::new(ProxyState::new(upstream)?);
    let addr: SocketAddr = ([127, 0, 0, 1], port).into();

    let listener = TcpListener::bind(addr)
        .await
        .with_context(|| format!("failed to bind to port {port}"))?;

    info!(%addr, upstream = %upstream, "LLM proxy listening");
    println!("guard proxy listening on http://{}", addr);
    println!("upstream: {}", upstream);
    println!(
        "Configure your LLM client to use http://{} as the API endpoint",
        addr
    );

    loop {
        match listener.accept().await {
            Ok((stream, remote_addr)) => {
                let state = Arc::clone(&state);
                let io = TokioIo::new(stream);

                tokio::spawn(async move {
                    let service = service_fn(move |req| {
                        let state = Arc::clone(&state);
                        async move { handle_request(state, req).await }
                    });

                    if let Err(e) = http1::Builder::new()
                        .serve_connection(io, service)
                        .await
                    {
                        warn!(%remote_addr, error = %e, "connection error");
                    }
                });
            }
            Err(e) => {
                error!(error = %e, "accept failed");
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_streaming_bool_true() {
        let body = br#"{"model": "gpt-4", "stream": true, "messages": []}"#;
        assert!(detect_streaming(body));
    }

    #[test]
    fn test_detect_streaming_bool_false() {
        let body = br#"{"model": "gpt-4", "stream": false, "messages": []}"#;
        assert!(!detect_streaming(body));
    }

    #[test]
    fn test_detect_streaming_int() {
        let body = br#"{"model": "gpt-4", "stream": 1, "messages": []}"#;
        assert!(detect_streaming(body));
    }

    #[test]
    fn test_detect_streaming_absent() {
        let body = br#"{"model": "gpt-4", "messages": []}"#;
        assert!(!detect_streaming(body));
    }

    #[test]
    fn test_detect_streaming_invalid_json() {
        let body = b"not json at all";
        assert!(!detect_streaming(body));
    }

    #[test]
    fn test_redact_sse_event_done() {
        let r = Redactor::new();
        assert_eq!(redact_sse_event(&r, "[DONE]"), "[DONE]");
    }

    #[test]
    fn test_redact_sse_ndjson_done() {
        let r = Redactor::new();
        let input = b"data: [DONE]\n";
        let out = redact_sse_ndjson(&r, input);
        // Convert Bytes to &str for substring contains checks.
        let s = std::str::from_utf8(&out).unwrap();
        assert!(s.contains("[DONE]"));
    }

    #[test]
    fn test_redact_sse_event_chat_chunk() {
        let r = Redactor::new();
        let event = r#"{"choices":[{"delta":{"content":"Hello world"}}]}"#;
        let out = redact_sse_event(&r, event);
        assert!(out.contains("Hello world"));
    }

    #[test]
    fn test_redact_sse_event_chat_chunk_with_secret() {
        let r = Redactor::new();
        let event = r#"{"choices":[{"delta":{"content":"API key: sk-1234567890abcdefghij"}}]}"#;
        let out = redact_sse_event(&r, event);
        assert!(!out.contains("sk-1234567890"));
        assert!(out.contains("[REDACTED]"));
    }

    #[test]
    fn test_redact_sse_event_legacy_completion() {
        let r = Redactor::new();
        let event = r#"{"choices":[{"text":"hello"}]}"#;
        let out = redact_sse_event(&r, event);
        assert!(out.contains("hello"));
    }

    #[test]
    fn test_redact_sse_event_legacy_completion_with_secret() {
        let r = Redactor::new();
        let event = r#"{"choices":[{"text":"secret=my_secret_token_123456789012"}]}"#;
        let out = redact_sse_event(&r, event);
        assert!(!out.contains("my_secret_token_123456789012"));
        assert!(out.contains("[REDACTED]"));
    }

    #[test]
    fn test_redact_sse_event_non_json() {
        let r = Redactor::new();
        let event = "some plain text with password=secret123";
        let out = redact_sse_event(&r, event);
        assert!(!out.contains("secret123"));
        assert!(out.contains("[REDACTED]"));
    }

    #[test]
    fn test_redact_sse_ndjson_full_stream() {
        let r = Redactor::new();
        let input = "\
data: {\"choices\":[{\"delta\":{\"content\":\"Hello \"}}]}
data: {\"choices\":[{\"delta\":{\"content\":\"API key: sk-abcdefghijklmnopqrst\"}}]}
data: [DONE]
";
        let out = redact_sse_ndjson(&r, input.as_bytes());
        let s = std::str::from_utf8(&out).unwrap();
        assert!(s.contains("Hello "));
        assert!(!s.contains("sk-abcdefghijklmnopqrst"));
        assert!(s.contains("[DONE]"));
    }
}
