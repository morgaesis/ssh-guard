//! The TLS-terminating proxy server loop. Accepts the agent's brokered
//! connection, terminates TLS with the ephemeral leaf, parses each request into
//! an [`ApiOp`], applies the operator [`ApiPolicy`], and either rejects it at the
//! proxy (deny/hold) or re-originates it to the real apiserver with the
//! operator's credentials. Secret reads are buffered, JSON-parsed, and redacted
//! before the response reaches the client; everything else streams through.
//!
//! Phase 1 scope: the read path plus the containment foundation. Interactive
//! subresources (`exec`/`attach`/`portforward`) and Secret `watch`es are denied
//! (their streams cannot be redacted yet); writes the policy allows are forwarded
//! without the auto-revert envelope (that lands in phase 2).

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use futures::TryStreamExt;
use http_body_util::{combinators::BoxBody, BodyExt, Full, Limited, StreamBody};
use hyper::body::{Bytes, Frame, Incoming};
use hyper::service::service_fn;
use hyper::{header, HeaderMap, Method, Request, Response, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use tokio::net::TcpListener;
use tokio::sync::RwLock;
use tokio_rustls::TlsAcceptor;

use super::k8s::{self, parse_api_op, Verb};
use super::policy::{ApiAction, ApiPolicy};
use super::tls::ProxyTls;
use super::upstream::Upstream;

/// Cap on a forwarded request body. Manifests are small; this bounds memory and
/// denies an oversized body from a misbehaving client.
const MAX_REQ_BODY: usize = 16 * 1024 * 1024;

/// How often the policy file is checked for changes (the operator "slow clock").
const POLICY_RELOAD_SECS: u64 = 5;

type ProxyBody = BoxBody<Bytes, Box<dyn std::error::Error + Send + Sync>>;

/// A configured Kubernetes API proxy: TLS identity, upstream connection, and the
/// hot-reloaded operator policy. Hosted by the daemon alongside the gate socket.
pub struct KubeProxy {
    listen: SocketAddr,
    proxy_url: String,
    tls: ProxyTls,
    upstream: Upstream,
    policy: Arc<RwLock<ApiPolicy>>,
    policy_path: Option<PathBuf>,
}

impl KubeProxy {
    /// Assemble a proxy. `policy_path` (when set) is hot-reloaded while serving;
    /// when unset, `policy` is used as-is (typically a default-deny).
    pub fn new(
        listen: SocketAddr,
        tls: ProxyTls,
        upstream: Upstream,
        policy: ApiPolicy,
        policy_path: Option<PathBuf>,
    ) -> Self {
        let proxy_url = format!("https://127.0.0.1:{}", listen.port());
        Self {
            listen,
            proxy_url,
            tls,
            upstream,
            policy: Arc::new(RwLock::new(policy)),
            policy_path,
        }
    }

    pub fn listen(&self) -> SocketAddr {
        self.listen
    }

    /// The loopback URL agents put in their brokered kubeconfig.
    pub fn proxy_url(&self) -> &str {
        &self.proxy_url
    }

    /// The agent-facing brokered kubeconfig (points at the proxy, no credential).
    pub fn brokered_kubeconfig(&self) -> String {
        super::kubeconfig::brokered_kubeconfig(&self.proxy_url, &self.tls.ca_data_b64())
    }

    /// Accept loop: terminate TLS and serve each connection. Returns only on a
    /// fatal bind error, so the daemon's listener supervision restarts the
    /// process the same way the gate socket does.
    pub async fn serve(self: Arc<Self>) -> Result<()> {
        let listener = TcpListener::bind(self.listen)
            .await
            .with_context(|| format!("bind kube-proxy listener on {}", self.listen))?;
        let acceptor = TlsAcceptor::from(self.tls.server_config());
        tracing::info!(
            "guard kube-proxy listening on https://{} -> {}",
            self.listen,
            self.upstream.base()
        );

        if let Some(path) = self.policy_path.clone() {
            let policy = self.policy.clone();
            tokio::spawn(async move { policy_reloader(path, policy).await });
        }

        loop {
            let (tcp, _peer) = match listener.accept().await {
                Ok(pair) => pair,
                Err(e) => {
                    tracing::warn!("kube-proxy accept error: {}", e);
                    continue;
                }
            };
            let acceptor = acceptor.clone();
            let me = self.clone();
            tokio::spawn(async move {
                let tls_stream = match acceptor.accept(tcp).await {
                    Ok(s) => s,
                    Err(e) => {
                        tracing::debug!("kube-proxy TLS handshake failed: {}", e);
                        return;
                    }
                };
                let io = TokioIo::new(tls_stream);
                let svc = service_fn(move |req| {
                    let me = me.clone();
                    async move { Ok::<_, std::convert::Infallible>(me.route(req).await) }
                });
                if let Err(e) = auto::Builder::new(TokioExecutor::new())
                    .serve_connection(io, svc)
                    .await
                {
                    tracing::debug!("kube-proxy connection error: {}", e);
                }
            });
        }
    }

    /// Classify and dispatch one request. Always returns a response (never errors
    /// the connection); upstream and policy failures become HTTP status bodies.
    async fn route(&self, req: Request<Incoming>) -> Response<ProxyBody> {
        let method = req.method().clone();
        let path = req.uri().path().to_string();
        let query = req.uri().query().unwrap_or("").to_string();

        let Some(op) = parse_api_op(method.as_str(), &path, &query) else {
            // Non-resource paths: discovery, /version, /openapi, /healthz. Clients
            // need these. Allow safe reads; block anything else.
            if method == Method::GET || method == Method::HEAD {
                return self.forward(req, &path, &query, false).await;
            }
            return status_resp(
                StatusCode::FORBIDDEN,
                "guard kube-proxy: non-resource write blocked",
                "Forbidden",
            );
        };

        // Interactive subresources tunnel arbitrary bytes and cannot be gated at
        // the request level yet: deny them outright in phase 1.
        if let Some(sub) = op.subresource.as_deref() {
            if matches!(sub, "exec" | "attach" | "portforward") {
                return status_resp(
                    StatusCode::FORBIDDEN,
                    &format!("guard kube-proxy: subresource '{sub}' is not permitted"),
                    "Forbidden",
                );
            }
        }

        // A Secret watch streams object events we cannot redact in phase 1, so it
        // would leak values: deny it regardless of policy.
        if op.is_secrets() && op.verb == Verb::Watch {
            return status_resp(
                StatusCode::FORBIDDEN,
                "guard kube-proxy: watching Secret values is not permitted",
                "Forbidden",
            );
        }

        let decision = self.policy.read().await.decide(&op);
        let label = format!("{} {}", op.verb.as_str(), path);
        match decision.action {
            ApiAction::Deny => {
                tracing::info!(target: "guard::kubeproxy", "DENY {} ({})", label, decision.reason);
                status_resp(
                    StatusCode::FORBIDDEN,
                    &format!("guard kube-proxy denied {label}: {}", decision.reason),
                    "Forbidden",
                )
            }
            ApiAction::Hold => {
                tracing::info!(target: "guard::kubeproxy", "HOLD {} ({})", label, decision.reason);
                status_resp(
                    StatusCode::FORBIDDEN,
                    &format!(
                        "guard kube-proxy: {label} held for operator approval: {}",
                        decision.reason
                    ),
                    "Forbidden",
                )
            }
            ApiAction::Allow => {
                let redact = decision.redact_secrets && op.is_secrets() && op.is_read();
                tracing::info!(target: "guard::kubeproxy", "ALLOW {}{}", label, if redact { " (redacting)" } else { "" });
                self.forward(req, &path, &query, redact).await
            }
        }
    }

    async fn forward(
        &self,
        req: Request<Incoming>,
        path: &str,
        query: &str,
        redact: bool,
    ) -> Response<ProxyBody> {
        match self.forward_inner(req, path, query, redact).await {
            Ok(resp) => resp,
            Err(e) => {
                tracing::warn!(target: "guard::kubeproxy", "upstream error for {path}: {e:#}");
                status_resp(
                    StatusCode::BAD_GATEWAY,
                    &format!("guard kube-proxy: upstream error: {e}"),
                    "InternalError",
                )
            }
        }
    }

    async fn forward_inner(
        &self,
        req: Request<Incoming>,
        path: &str,
        query: &str,
        redact: bool,
    ) -> Result<Response<ProxyBody>> {
        let (parts, body) = req.into_parts();

        let collected = Limited::new(body, MAX_REQ_BODY)
            .collect()
            .await
            .map_err(|e| anyhow!("read request body (limit {MAX_REQ_BODY}): {e}"))?
            .to_bytes();

        let url = if query.is_empty() {
            format!("{}{}", self.upstream.base(), path)
        } else {
            format!("{}{}?{}", self.upstream.base(), path, query)
        };

        let mut rb = self.upstream.client().request(parts.method.clone(), &url);
        for (name, value) in parts.headers.iter() {
            if is_hop_by_hop(name)
                || name == header::HOST
                || name == header::AUTHORIZATION
                || name == header::COOKIE
                || name == header::CONTENT_LENGTH
            {
                continue;
            }
            // For a redacted Secret read we force JSON so the body is parseable;
            // drop the client's Accept and set our own below.
            if redact && name == header::ACCEPT {
                continue;
            }
            rb = rb.header(name, value);
        }
        if redact {
            rb = rb.header(header::ACCEPT, "application/json");
        }
        if let Some(token) = self.upstream.bearer() {
            rb = rb.bearer_auth(token);
        }
        if !collected.is_empty() {
            rb = rb.body(collected);
        }

        let upstream_resp = rb.send().await.context("forward to apiserver")?;
        let status = upstream_resp.status();
        let upstream_headers = upstream_resp.headers().clone();

        let mut builder = Response::builder().status(status);
        if let Some(hdrs) = builder.headers_mut() {
            for (name, value) in upstream_headers.iter() {
                // Strip hop-by-hop and framing headers; hyper re-frames the body.
                if is_hop_by_hop(name)
                    || name == header::CONTENT_LENGTH
                    || name == header::TRANSFER_ENCODING
                {
                    continue;
                }
                hdrs.append(name, value.clone());
            }
        }

        if redact && status.is_success() && is_json(&upstream_headers) {
            let bytes = upstream_resp
                .bytes()
                .await
                .context("read Secret response for redaction")?;
            let mut value: serde_json::Value = match serde_json::from_slice(&bytes) {
                Ok(v) => v,
                // Fail closed: never pass an unparsed Secret body through.
                Err(_) => {
                    return Ok(status_resp(
                        StatusCode::BAD_GATEWAY,
                        "guard kube-proxy: could not parse Secret response for redaction",
                        "InternalError",
                    ));
                }
            };
            let n = k8s::redact_secret_response(&mut value);
            tracing::info!(target: "guard::kubeproxy", "redacted {n} Secret object(s) on {path}");
            let out = serde_json::to_vec(&value).context("re-serialize redacted Secret")?;
            return Ok(builder
                .body(full_body(Bytes::from(out)))
                .expect("build redacted response"));
        }

        // Stream the response body through unchanged (lists, gets, watches).
        let stream = upstream_resp
            .bytes_stream()
            .map_ok(Frame::data)
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>);
        let body = StreamBody::new(stream).boxed();
        Ok(builder.body(body).expect("build streamed response"))
    }
}

/// Build a Kubernetes `Status` error body so clients (kubectl/helm) surface a
/// clean message instead of a transport error.
fn status_resp(code: StatusCode, message: &str, reason: &str) -> Response<ProxyBody> {
    let status = serde_json::json!({
        "kind": "Status",
        "apiVersion": "v1",
        "metadata": {},
        "status": "Failure",
        "message": message,
        "reason": reason,
        "code": code.as_u16(),
    });
    let body = full_body(Bytes::from(status.to_string()));
    Response::builder()
        .status(code)
        .header(header::CONTENT_TYPE, "application/json")
        .body(body)
        .expect("build status response")
}

fn full_body(bytes: Bytes) -> ProxyBody {
    Full::new(bytes).map_err(|never| match never {}).boxed()
}

/// RFC 7230 hop-by-hop headers, which must not be forwarded by a proxy.
fn is_hop_by_hop(name: &header::HeaderName) -> bool {
    matches!(
        name.as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    )
}

fn is_json(headers: &HeaderMap) -> bool {
    headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|ct| ct.trim_start().starts_with("application/json"))
        .unwrap_or(false)
}

/// Reload the policy file when its mtime changes (the operator slow clock). A
/// parse error keeps the last good policy in force and is logged.
async fn policy_reloader(path: PathBuf, policy: Arc<RwLock<ApiPolicy>>) {
    let mut last = std::fs::metadata(&path).and_then(|m| m.modified()).ok();
    loop {
        tokio::time::sleep(Duration::from_secs(POLICY_RELOAD_SECS)).await;
        let modified = std::fs::metadata(&path).and_then(|m| m.modified()).ok();
        if modified == last {
            continue;
        }
        last = modified;
        match ApiPolicy::load_file(&path) {
            Ok(p) => {
                *policy.write().await = p;
                tracing::info!(target: "guard::kubeproxy", "reloaded api-policy from {}", path.display());
            }
            Err(e) => {
                tracing::error!(
                    target: "guard::kubeproxy",
                    "api-policy reload failed ({}); keeping previous policy: {e}",
                    path.display()
                );
            }
        }
    }
}
