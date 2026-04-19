//! Guard server mode - accepts command execution requests and runs them with privileged access.
//!
//! The server listens on a UNIX socket or TCP port and accepts requests from clients (agents).
//! Each request is evaluated against the policy engine before execution.
//!
//! Security model:
//! - UNIX socket: peer UID-based authorization
//! - TCP socket: auth token required
//! - Socket dir: 0755 when managed by socket_group
//! - Socket: 0666 so local clients can connect before UID validation

use crate::evaluate::Evaluator;
use crate::redact::{
    redact_exact_secrets, redact_output_text, redact_output_with_state, RedactionState,
};
use crate::secrets::SecretManager;
use crate::session::{SessionDecision, SessionGrant, SessionGrantSummary, SessionRegistry};
use crate::tool_config::ToolRegistry;
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, UnixListener, UnixStream};
use tokio::process::Command;
use tokio::sync::{mpsc, RwLock};

const DEFAULT_SOCKET_PATH: &str = "/var/run/guard/guard.sock";
const DEFAULT_TCP_PORT: u16 = 8123;
const MAX_GUARD_DEPTH: u32 = 5;
const MAX_REQUEST_BYTES: usize = 1_048_576; // 1MB
const MAX_OUTPUT_BYTES: usize = 10_485_760; // 10MB

/// Identifies the caller for per-user secret injection.
#[derive(Debug, Clone)]
pub enum CallerIdentity {
    Unix { uid: u32 },
    Tcp { token: String },
    Unknown,
}

impl CallerIdentity {
    /// Returns the key used to look up per-user config in tools.yaml.
    pub fn user_key(&self) -> Option<String> {
        match self {
            Self::Unix { uid } => Some(uid.to_string()),
            Self::Tcp { token } => Some(token.clone()),
            Self::Unknown => None,
        }
    }
}

impl std::fmt::Display for CallerIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unix { uid } => write!(f, "uid={}", uid),
            Self::Tcp { token } => {
                let redacted = if token.len() > 8 {
                    format!("{}...{}", &token[..4], &token[token.len() - 4..])
                } else {
                    "***".to_string()
                };
                write!(f, "token={}", redacted)
            }
            Self::Unknown => write!(f, "unknown"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecuteRequest {
    pub binary: String,
    pub args: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_token: Option<String>,
    #[serde(default)]
    pub stream: bool,
    /// Session grant token. When present and matched server-side, session
    /// allow/deny patterns short-circuit the decision before the evaluator.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_token: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
#[allow(clippy::enum_variant_names)]
pub enum AdminRequest {
    SessionGrant {
        token: String,
        #[serde(default)]
        allow: Vec<String>,
        #[serde(default)]
        deny: Vec<String>,
        #[serde(default)]
        ttl_secs: Option<u64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        prompt_append: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        auth_token: Option<String>,
    },
    SessionRevoke {
        token: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        auth_token: Option<String>,
    },
    SessionList {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        auth_token: Option<String>,
    },
}

impl AdminRequest {
    fn auth_token(&self) -> Option<&str> {
        match self {
            Self::SessionGrant { auth_token, .. }
            | Self::SessionRevoke { auth_token, .. }
            | Self::SessionList { auth_token, .. } => auth_token.as_deref(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum AdminResponse {
    Ok,
    Error { message: String },
    SessionList { grants: Vec<SessionGrantSummary> },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
enum IncomingMessage {
    Admin {
        admin: AdminRequest,
    },
    Execute(ExecuteRequest),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecuteResponse {
    pub allowed: bool,
    pub reason: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stdout: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stderr: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum ExecuteStreamMessage {
    Stdout { data: String },
    Stderr { data: String },
    PolicyDecision { allowed: bool, reason: String },
    Keepalive,
    Result { response: ExecuteResponse },
}

#[derive(Debug, Clone, Copy)]
pub enum OutputStream {
    Stdout,
    Stderr,
}

#[derive(Clone)]
pub struct ServerConfig {
    pub socket_path: Option<PathBuf>,
    pub tcp_port: Option<u16>,
    pub evaluator: Arc<Evaluator>,
    pub secrets: Arc<SecretManager>,
    pub redact: bool,
    pub auth_token: Option<String>,
    pub socket_group: Option<String>,
    pub allowed_uids: Option<Vec<u32>>,
    pub shim_dir: Option<PathBuf>,
    pub dry_run: bool,
    pub tool_registry: Arc<RwLock<ToolRegistry>>,
    /// Known secret values for exact-match output redaction.
    pub redact_secrets: Vec<String>,
    /// When true, run deterministic pre-LLM checks (executable existence on
    /// PATH, credential-disclosure pattern deny). When false, the evaluator
    /// is the only authority on whether a command is allowed.
    pub preflight: bool,
    /// Session grant registry. Grants here extend or narrow the policy
    /// decision for a specific session token.
    pub sessions: Arc<RwLock<SessionRegistry>>,
}

impl ServerConfig {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        socket_path: Option<PathBuf>,
        tcp_port: Option<u16>,
        evaluator: Evaluator,
        secrets: SecretManager,
        redact: bool,
        auth_token: Option<String>,
        socket_group: Option<String>,
        allowed_uids: Option<Vec<u32>>,
        shim_dir: Option<PathBuf>,
        dry_run: bool,
        tool_registry: ToolRegistry,
        redact_secrets: Vec<String>,
        preflight: bool,
    ) -> Self {
        Self {
            socket_path,
            tcp_port,
            evaluator: Arc::new(evaluator),
            secrets: Arc::new(secrets),
            redact,
            auth_token,
            socket_group,
            allowed_uids,
            shim_dir,
            dry_run,
            tool_registry: Arc::new(RwLock::new(tool_registry)),
            redact_secrets,
            preflight,
            sessions: Arc::new(RwLock::new(SessionRegistry::new())),
        }
    }

    fn validate_uid(&self, uid: u32) -> Result<()> {
        if let Some(ref allowed) = self.allowed_uids {
            if !allowed.contains(&uid) {
                tracing::warn!("connection rejected: uid {} not in allowed list", uid);
                anyhow::bail!("connection not allowed for this user");
            }
        }
        Ok(())
    }

    fn validate_token(&self, token: Option<&str>) -> Result<()> {
        if let Some(ref expected) = self.auth_token {
            let provided = token.unwrap_or("").as_bytes();
            let expected = expected.as_bytes();
            // Constant-time comparison to prevent timing side-channel
            let len_match = provided.len() == expected.len();
            let byte_match = provided
                .iter()
                .zip(expected.iter())
                .fold(0u8, |acc, (a, b)| acc | (a ^ b));
            if !len_match || byte_match != 0 {
                anyhow::bail!("invalid auth token");
            }
        }
        Ok(())
    }

    /// Log the LLM policy decision. This is the primary audit event and
    /// uses the historical `[AUDIT] ALLOWED` / `[AUDIT] DENIED` prefixes
    /// so existing grep patterns (harness scripts, review agents) keep
    /// working. It reflects only the policy verdict, not whether the
    /// command subsequently managed to exec.
    fn log_audit_policy(
        &self,
        caller: &CallerIdentity,
        binary: &str,
        args: &[String],
        allowed: bool,
        reason: &str,
    ) {
        let action = if allowed { "ALLOWED" } else { "DENIED" };
        tracing::info!(
            "[AUDIT] {} caller={} cmd=\"{} {}\" reason=\"{}\"",
            action,
            caller,
            binary,
            args.join(" "),
            reason
        );
    }

    /// Log a failed exec attempt. Only emitted when the policy allowed
    /// the command but the kernel refused to run it (ENOENT, EACCES,
    /// etc.). Paired with a corresponding `[AUDIT] ALLOWED` line so
    /// downstream tooling can distinguish "policy denied" from "policy
    /// approved, exec failed".
    fn log_audit_exec_failed(
        &self,
        caller: &CallerIdentity,
        binary: &str,
        args: &[String],
        reason: &str,
    ) {
        tracing::info!(
            "[AUDIT] EXEC_FAILED caller={} cmd=\"{} {}\" reason=\"{}\"",
            caller,
            binary,
            args.join(" "),
            reason
        );
    }
}

#[derive(Clone)]
#[allow(dead_code)]
pub struct Server {
    config: ServerConfig,
}

impl Server {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        socket_path: Option<PathBuf>,
        tcp_port: Option<u16>,
        evaluator: Evaluator,
        secrets: SecretManager,
        redact: bool,
        auth_token: Option<String>,
        socket_group: Option<String>,
        allowed_uids: Option<Vec<u32>>,
        shim_dir: Option<PathBuf>,
        dry_run: bool,
        tool_registry: ToolRegistry,
        redact_secrets: Vec<String>,
        preflight: bool,
    ) -> Self {
        let config = ServerConfig::new(
            socket_path,
            tcp_port,
            evaluator,
            secrets,
            redact,
            auth_token,
            socket_group,
            allowed_uids,
            shim_dir,
            dry_run,
            tool_registry,
            redact_secrets,
            preflight,
        );
        Self { config }
    }

    pub async fn run(&self) -> Result<()> {
        tracing::info!("Server::run() called");

        let mut futures = Vec::new();

        if let Some(ref socket_path) = self.config.socket_path {
            tracing::info!("Starting UNIX socket listener on {}", socket_path.display());
            let path = socket_path.clone();
            let config = self.config.clone();
            futures.push(tokio::spawn(async move {
                Self::run_unix_static(&path, &config).await
            }));
        }

        if let Some(port) = self.config.tcp_port {
            tracing::info!("Starting TCP listener on port {}", port);
            let config = self.config.clone();
            futures.push(tokio::spawn(async move {
                Self::run_tcp_static(port, &config).await
            }));
        }

        if futures.is_empty() {
            anyhow::bail!("no socket path or TCP port specified");
        }

        let _ = futures::future::join_all(futures).await;

        Ok(())
    }

    async fn run_unix_static(socket_path: &PathBuf, config: &ServerConfig) -> Result<()> {
        if let Some(parent) = socket_path.parent() {
            tokio::fs::create_dir_all(parent)
                .await
                .context("failed to create socket directory")?;
        }

        if socket_path.exists() {
            tokio::fs::remove_file(socket_path).await?;
        }

        let listener = UnixListener::bind(socket_path).context("failed to bind UNIX socket")?;
        Self::chmod_path(socket_path, 0o666).await?;

        tracing::info!("guard server listening on {}", socket_path.display());

        if let Some(ref group) = config.socket_group {
            Self::chown_to_group(socket_path, group).await?;
            if let Some(parent) = socket_path.parent() {
                Self::chmod_path(parent, 0o755).await?;
            }
        }

        loop {
            match listener.accept().await {
                Ok((stream, _peer_addr)) => {
                    let config = config.clone();

                    tokio::spawn(async move {
                        if let Err(e) = handle_client_unix(stream, &config).await {
                            tracing::error!("client handler error: {}", e);
                        }
                    });
                }
                Err(e) => {
                    tracing::error!("accept error: {}", e);
                }
            }
        }
    }

    async fn run_tcp_static(port: u16, config: &ServerConfig) -> Result<()> {
        let addr = format!("127.0.0.1:{}", port);
        let listener = TcpListener::bind(&addr)
            .await
            .context("failed to bind TCP socket")?;

        tracing::info!("guard server listening on tcp://{}", addr);

        loop {
            match listener.accept().await {
                Ok((stream, _)) => {
                    let config = config.clone();

                    tokio::spawn(async move {
                        if let Err(e) = handle_client_tcp(stream, &config).await {
                            tracing::error!("client handler error: {}", e);
                        }
                    });
                }
                Err(e) => {
                    tracing::error!("accept error: {}", e);
                }
            }
        }
    }

    async fn chown_to_group(path: &PathBuf, group: &str) -> Result<()> {
        let output = Command::new("chgrp").arg(group).arg(path).output().await?;

        if !output.status.success() {
            bail!(
                "failed to change group of {} to {}: {}",
                path.display(),
                group,
                String::from_utf8_lossy(&output.stderr)
            );
        }
        Ok(())
    }

    async fn chmod_path(path: &std::path::Path, mode: u32) -> Result<()> {
        let permissions = std::fs::Permissions::from_mode(mode);
        std::fs::set_permissions(path, permissions)
            .with_context(|| format!("failed to chmod {} to {:o}", path.display(), mode))?;
        Ok(())
    }
}

async fn handle_client_unix(stream: UnixStream, config: &ServerConfig) -> Result<()> {
    tracing::info!("handle_client_unix: new connection");
    let uid = stream
        .peer_cred()
        .context("failed to read peer credentials")?
        .uid();
    tracing::info!("handle_client_unix: peer uid = {}", uid);

    if let Err(e) = config.validate_uid(uid) {
        tracing::warn!("uid {} rejected: {}", uid, e);
        return Err(e);
    }

    tracing::info!("handle_client_unix: uid validated");
    let (reader, mut writer) = stream.into_split();
    let mut lines = BufReader::new(reader).lines();

    tracing::info!("handle_client_unix: waiting for request...");
    while let Ok(Some(line)) = lines.next_line().await {
        if line.len() > MAX_REQUEST_BYTES {
            tracing::warn!("request too large ({} bytes), dropping", line.len());
            continue;
        }
        tracing::debug!("handle_client_unix: received request (raw)");
        let incoming: IncomingMessage = match serde_json::from_str(&line) {
            Ok(r) => r,
            Err(e) => {
                let resp = ExecuteResponse {
                    allowed: false,
                    reason: format!("invalid request: {}", e),
                    exit_code: None,
                    stdout: None,
                    stderr: None,
                };
                writer
                    .write_all(serde_json::to_string(&resp)?.as_bytes())
                    .await?;
                writer.write_all(b"\n").await?;
                continue;
            }
        };

        let caller = CallerIdentity::Unix { uid };

        let request = match incoming {
            IncomingMessage::Admin { admin } => {
                let resp = handle_admin_request(config, &caller, admin).await;
                writer
                    .write_all(serde_json::to_string(&resp)?.as_bytes())
                    .await?;
                writer.write_all(b"\n").await?;
                continue;
            }
            IncomingMessage::Execute(req) => req,
        };

        if let Err(_e) = config.validate_token(request.auth_token.as_deref()) {
            config.log_audit_policy(
                &caller,
                &request.binary,
                &request.args,
                false,
                "invalid auth token",
            );
            let resp = ExecuteResponse {
                allowed: false,
                reason: "invalid auth token".to_string(),
                exit_code: None,
                stdout: None,
                stderr: None,
            };
            writer
                .write_all(serde_json::to_string(&resp)?.as_bytes())
                .await?;
            writer.write_all(b"\n").await?;
            continue;
        }

        let result = if request.stream {
            execute_command_streaming(request.clone(), config, &caller, &mut writer).await
        } else {
            execute_command(request.clone(), config, &caller).await
        };
        emit_exec_audit_events(config, &caller, &request.binary, &request.args, &result);

        let resp = result.into_response();
        if request.stream {
            write_stream_message(
                &mut writer,
                &ExecuteStreamMessage::Result { response: resp },
            )
            .await?;
        } else {
            writer
                .write_all(serde_json::to_string(&resp)?.as_bytes())
                .await?;
            writer.write_all(b"\n").await?;
        }
    }

    Ok(())
}

/// Emit POLICY and (optionally) EXEC_FAILED audit events for a single
/// request. Keeps both handlers aligned so the format stays consistent
/// whether the caller came in over UNIX or TCP.
fn emit_audit_events(
    config: &ServerConfig,
    caller: &CallerIdentity,
    binary: &str,
    args: &[String],
    result: &ExecuteResult,
) {
    // Always emit the policy decision — this is the event historical
    // grep patterns (`[AUDIT] ALLOWED` / `[AUDIT] DENIED`) key on.
    config.log_audit_policy(
        caller,
        binary,
        args,
        result.policy_allowed(),
        result.policy_reason(),
    );

    // If the policy allowed but exec failed, emit a second event so the
    // audit stream can distinguish "LLM denied" from "LLM approved but
    // exec failed". Ignored by legacy grep patterns.
    if let ExecOutcome::Failed { reason } = &result.exec {
        config.log_audit_exec_failed(caller, binary, args, reason);
    }
}

fn emit_exec_audit_events(
    config: &ServerConfig,
    caller: &CallerIdentity,
    binary: &str,
    args: &[String],
    result: &ExecuteResult,
) {
    if let ExecOutcome::Failed { reason } = &result.exec {
        config.log_audit_exec_failed(caller, binary, args, reason);
    }
}

async fn handle_admin_request(
    config: &ServerConfig,
    caller: &CallerIdentity,
    request: AdminRequest,
) -> AdminResponse {
    if let Err(e) = config.validate_token(request.auth_token()) {
        tracing::warn!(
            "admin request rejected: caller={} reason={}",
            caller,
            e
        );
        return AdminResponse::Error {
            message: "invalid auth token".to_string(),
        };
    }

    match request {
        AdminRequest::SessionGrant {
            token,
            allow,
            deny,
            ttl_secs,
            prompt_append,
            ..
        } => {
            if token.is_empty() {
                return AdminResponse::Error {
                    message: "session token must not be empty".to_string(),
                };
            }
            let expires_at = ttl_secs.map(|secs| {
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0)
                    + secs
            });
            let grant = SessionGrant {
                allow,
                deny,
                expires_at,
                prompt_append,
            };
            let mut reg = config.sessions.write().await;
            reg.purge_expired();
            reg.grant(token.clone(), grant);
            tracing::info!(
                "[AUDIT] SESSION_GRANT caller={} token={} ttl={:?}",
                caller,
                token,
                ttl_secs
            );
            AdminResponse::Ok
        }
        AdminRequest::SessionRevoke { token, .. } => {
            let mut reg = config.sessions.write().await;
            let removed = reg.revoke(&token);
            tracing::info!(
                "[AUDIT] SESSION_REVOKE caller={} token={} existed={}",
                caller,
                token,
                removed
            );
            AdminResponse::Ok
        }
        AdminRequest::SessionList { .. } => {
            let reg = config.sessions.read().await;
            AdminResponse::SessionList {
                grants: reg.list(),
            }
        }
    }
}

async fn handle_client_tcp(stream: tokio::net::TcpStream, config: &ServerConfig) -> Result<()> {
    let (reader, mut writer) = stream.into_split();
    let mut lines = BufReader::new(reader).lines();

    while let Ok(Some(line)) = lines.next_line().await {
        if line.len() > MAX_REQUEST_BYTES {
            tracing::warn!("request too large ({} bytes), dropping", line.len());
            continue;
        }
        let incoming: IncomingMessage = match serde_json::from_str(&line) {
            Ok(r) => r,
            Err(e) => {
                let resp = ExecuteResponse {
                    allowed: false,
                    reason: format!("invalid request: {}", e),
                    exit_code: None,
                    stdout: None,
                    stderr: None,
                };
                writer
                    .write_all(serde_json::to_string(&resp)?.as_bytes())
                    .await?;
                writer.write_all(b"\n").await?;
                continue;
            }
        };

        let request = match incoming {
            IncomingMessage::Admin { admin } => {
                let caller = CallerIdentity::Tcp {
                    token: admin
                        .auth_token()
                        .map(|s| s.to_string())
                        .unwrap_or_else(|| "<none>".to_string()),
                };
                let resp = handle_admin_request(config, &caller, admin).await;
                writer
                    .write_all(serde_json::to_string(&resp)?.as_bytes())
                    .await?;
                writer.write_all(b"\n").await?;
                continue;
            }
            IncomingMessage::Execute(req) => req,
        };

        if let Err(_e) = config.validate_token(request.auth_token.as_deref()) {
            let caller = CallerIdentity::Unknown;
            config.log_audit_policy(
                &caller,
                &request.binary,
                &request.args,
                false,
                "invalid auth token",
            );
            let resp = ExecuteResponse {
                allowed: false,
                reason: "invalid auth token".to_string(),
                exit_code: None,
                stdout: None,
                stderr: None,
            };
            writer
                .write_all(serde_json::to_string(&resp)?.as_bytes())
                .await?;
            writer.write_all(b"\n").await?;
            continue;
        }

        let caller = CallerIdentity::Tcp {
            token: request
                .auth_token
                .clone()
                .unwrap_or_else(|| "<none>".to_string()),
        };
        let result = if request.stream {
            execute_command_streaming(request.clone(), config, &caller, &mut writer).await
        } else {
            execute_command(request.clone(), config, &caller).await
        };
        emit_exec_audit_events(config, &caller, &request.binary, &request.args, &result);

        let resp = result.into_response();
        if request.stream {
            write_stream_message(
                &mut writer,
                &ExecuteStreamMessage::Result { response: resp },
            )
            .await?;
        } else {
            writer
                .write_all(serde_json::to_string(&resp)?.as_bytes())
                .await?;
            writer.write_all(b"\n").await?;
        }
    }

    Ok(())
}

/// Policy-level outcome: did the LLM/static engine approve the command?
/// This is distinct from whether the command actually managed to run.
#[derive(Debug, Clone)]
enum PolicyOutcome {
    /// LLM allowed the command. `reason` is the rationale returned by the
    /// evaluator.
    Allowed { reason: String },
    /// LLM denied the command, or the evaluator itself errored. `reason`
    /// carries the message surfaced to the client and audit log.
    Denied { reason: String },
}

/// Execution-level outcome: attempted only when `PolicyOutcome::Allowed`.
#[derive(Debug, Clone)]
enum ExecOutcome {
    /// Command was never attempted (policy denied it first).
    NotAttempted,
    /// Command ran; exit_code and captured streams are present.
    Completed {
        exit_code: Option<i32>,
        stdout: Option<String>,
        stderr: Option<String>,
    },
    /// Policy approved, but spawning/running the child failed. `reason`
    /// describes the OS-level error (e.g. ENOENT on the binary).
    Failed { reason: String },
    /// Policy approved, but the server intentionally did not spawn the child.
    DryRun,
}

struct ExecuteResult {
    policy: PolicyOutcome,
    exec: ExecOutcome,
}

impl ExecuteResult {
    fn denied(reason: impl Into<String>) -> Self {
        Self {
            policy: PolicyOutcome::Denied {
                reason: reason.into(),
            },
            exec: ExecOutcome::NotAttempted,
        }
    }

    /// Convenience constructor for "policy approved and exec completed".
    fn completed(
        reason: impl Into<String>,
        exit_code: Option<i32>,
        stdout: Option<String>,
        stderr: Option<String>,
    ) -> Self {
        Self {
            policy: PolicyOutcome::Allowed {
                reason: reason.into(),
            },
            exec: ExecOutcome::Completed {
                exit_code,
                stdout,
                stderr,
            },
        }
    }

    /// Convenience constructor for "policy approved but exec failed".
    fn exec_failed(policy_reason: impl Into<String>, exec_reason: impl Into<String>) -> Self {
        Self {
            policy: PolicyOutcome::Allowed {
                reason: policy_reason.into(),
            },
            exec: ExecOutcome::Failed {
                reason: exec_reason.into(),
            },
        }
    }

    fn dry_run(reason: impl Into<String>) -> Self {
        Self {
            policy: PolicyOutcome::Allowed {
                reason: reason.into(),
            },
            exec: ExecOutcome::DryRun,
        }
    }

    /// True if the policy approved the command. Note: this does NOT mean
    /// the command actually ran — check the exec outcome for that.
    fn policy_allowed(&self) -> bool {
        matches!(self.policy, PolicyOutcome::Allowed { .. })
    }

    /// Reason for the policy decision (allow rationale or denial reason).
    fn policy_reason(&self) -> &str {
        match &self.policy {
            PolicyOutcome::Allowed { reason } | PolicyOutcome::Denied { reason } => reason,
        }
    }

    /// Build the `ExecuteResponse` wire payload. Callers that need to emit
    /// audit events first should do so before consuming the result.
    fn into_response(self) -> ExecuteResponse {
        let allowed = self.policy_allowed();
        match self.exec {
            ExecOutcome::Completed {
                exit_code,
                stdout,
                stderr,
            } => ExecuteResponse {
                allowed: true,
                reason: match self.policy {
                    PolicyOutcome::Allowed { reason } => reason,
                    PolicyOutcome::Denied { reason } => reason,
                },
                exit_code,
                stdout,
                stderr,
            },
            ExecOutcome::Failed { reason: exec_msg } => ExecuteResponse {
                // Even though the policy allowed it, the command could not
                // actually run. Surface this to the client as `allowed=false`
                // with the exec error as the reason, because from the
                // client's perspective nothing ran successfully. The audit
                // stream still records both POLICY=ALLOWED and EXEC_FAILED.
                allowed: false,
                reason: format!("execution error: {}", exec_msg),
                exit_code: None,
                stdout: None,
                stderr: None,
            },
            ExecOutcome::DryRun => ExecuteResponse {
                allowed: true,
                reason: match self.policy {
                    PolicyOutcome::Allowed { reason } => reason,
                    PolicyOutcome::Denied { reason } => reason,
                },
                exit_code: Some(0),
                stdout: Some("[DRY-RUN] policy allowed; command was not executed\n".to_string()),
                stderr: None,
            },
            ExecOutcome::NotAttempted => ExecuteResponse {
                allowed,
                reason: match self.policy {
                    PolicyOutcome::Allowed { reason } => reason,
                    PolicyOutcome::Denied { reason } => reason,
                },
                exit_code: None,
                stdout: None,
                stderr: None,
            },
        }
    }
}

async fn write_stream_message<W: AsyncWrite + Unpin>(
    writer: &mut W,
    message: &ExecuteStreamMessage,
) -> Result<()> {
    writer
        .write_all(serde_json::to_string(message)?.as_bytes())
        .await?;
    writer.write_all(b"\n").await?;
    writer.flush().await?;
    Ok(())
}

async fn write_policy_decision<W: AsyncWrite + Unpin>(
    stream_output: bool,
    writer: &mut W,
    allowed: bool,
    reason: &str,
) -> Result<()> {
    if stream_output {
        write_stream_message(
            writer,
            &ExecuteStreamMessage::PolicyDecision {
                allowed,
                reason: reason.to_string(),
            },
        )
        .await?;
    }
    Ok(())
}

async fn execute_command(
    request: ExecuteRequest,
    config: &ServerConfig,
    caller: &CallerIdentity,
) -> ExecuteResult {
    let mut sink = tokio::io::sink();
    execute_command_inner(request, config, caller, false, &mut sink).await
}

async fn execute_command_streaming<W: AsyncWrite + Unpin>(
    request: ExecuteRequest,
    config: &ServerConfig,
    caller: &CallerIdentity,
    writer: &mut W,
) -> ExecuteResult {
    execute_command_inner(request, config, caller, true, writer).await
}

async fn execute_command_inner<W: AsyncWrite + Unpin>(
    request: ExecuteRequest,
    config: &ServerConfig,
    caller: &CallerIdentity,
    stream_output: bool,
    stream_writer: &mut W,
) -> ExecuteResult {
    // Check recursion depth
    let depth: u32 = std::env::var("GUARD_DEPTH")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    if depth >= MAX_GUARD_DEPTH {
        let reason = format!("guard recursion depth exceeded (max {})", MAX_GUARD_DEPTH);
        config.log_audit_policy(caller, &request.binary, &request.args, false, &reason);
        let _ = write_policy_decision(stream_output, stream_writer, false, &reason).await;
        return ExecuteResult::denied(reason);
    }

    // Validate binary name: reject paths, traversal, and shell metacharacters
    if request.binary.contains('/')
        || request.binary.contains("..")
        || request.binary.contains('\0')
        || request.binary.is_empty()
    {
        let reason = format!("invalid binary name: '{}'", request.binary);
        config.log_audit_policy(caller, &request.binary, &request.args, false, &reason);
        let _ = write_policy_decision(stream_output, stream_writer, false, &reason).await;
        return ExecuteResult::denied(reason);
    }

    // Reconstruct full command line early so session short-circuit and
    // evaluator share the same command text.
    let command_line = if request.args.is_empty() {
        request.binary.clone()
    } else {
        format!("{} {}", request.binary, request.args.join(" "))
    };

    // Session grants short-circuit both directions: deny wins before the
    // evaluator, allow skips the evaluator entirely.
    if let Some(ref token) = request.session_token {
        let decision = {
            let reg = config.sessions.read().await;
            reg.check(token, &request.binary, &request.args)
        };
        if let Some((decision, reason)) = decision {
            match decision {
                SessionDecision::Deny => {
                    config.log_audit_policy(caller, &request.binary, &request.args, false, &reason);
                    let _ = write_policy_decision(stream_output, stream_writer, false, &reason).await;
                    return ExecuteResult::denied(reason);
                }
                SessionDecision::Allow => {
                    config.log_audit_policy(caller, &request.binary, &request.args, true, &reason);
                    if let Err(e) = write_policy_decision(stream_output, stream_writer, true, &reason).await {
                        return ExecuteResult::exec_failed(reason, format!("client stream error: {}", e));
                    }
                    return exec_after_approval(
                        request,
                        config,
                        caller,
                        reason,
                        depth,
                        stream_output,
                        stream_writer,
                    )
                    .await;
                }
            }
        }
    }

    if config.preflight && !binary_exists_on_path(&request.binary) {
        let reason = format!(
            "unknown binary: '{}' is not available on the guard server PATH",
            request.binary
        );
        config.log_audit_policy(caller, &request.binary, &request.args, false, &reason);
        let _ = write_policy_decision(stream_output, stream_writer, false, &reason).await;
        return ExecuteResult::denied(reason);
    }

    if config.preflight {
        if let Some(reason) = deterministic_credential_deny_reason(&request.binary, &request.args) {
            config.log_audit_policy(caller, &request.binary, &request.args, false, &reason);
            let _ = write_policy_decision(stream_output, stream_writer, false, &reason).await;
            return ExecuteResult::denied(reason);
        }
    }

    // Pull session-scoped additive prompt, if any. The evaluator appends
    // it to the system prompt for this single call so the LLM has the
    // session context that the static glob patterns cannot express.
    let session_prompt = if let Some(ref token) = request.session_token {
        let reg = config.sessions.read().await;
        reg.prompt_append_for(token)
    } else {
        None
    };

    let eval_result = config
        .evaluator
        .evaluate_with_context(&command_line, session_prompt.as_deref())
        .await;

    let allow_reason = match eval_result {
        crate::evaluate::EvalResult::Deny { reason, .. } => {
            config.log_audit_policy(caller, &request.binary, &request.args, false, &reason);
            let _ = write_policy_decision(stream_output, stream_writer, false, &reason).await;
            return ExecuteResult::denied(reason);
        }
        crate::evaluate::EvalResult::Error(e) => {
            tracing::error!("evaluation error: {}", e);
            let reason = format!("evaluation error: {}", e);
            config.log_audit_policy(caller, &request.binary, &request.args, false, &reason);
            let _ = write_policy_decision(stream_output, stream_writer, false, &reason).await;
            return ExecuteResult::denied(reason);
        }
        crate::evaluate::EvalResult::Allow { reason, .. } => {
            tracing::debug!("command allowed: {}", reason);
            config.log_audit_policy(caller, &request.binary, &request.args, true, &reason);
            if let Err(e) = write_policy_decision(stream_output, stream_writer, true, &reason).await
            {
                return ExecuteResult::exec_failed(reason, format!("client stream error: {}", e));
            }
            reason
        }
    };

    exec_after_approval(
        request,
        config,
        caller,
        allow_reason,
        depth,
        stream_output,
        stream_writer,
    )
    .await
}

/// Execute a command the policy layer has already approved.
///
/// Entered from either the LLM evaluator path or a session-grant allow
/// match. Failures returned from here are exec-level, not policy-level,
/// so the audit stream can tell "policy said no" apart from "policy
/// said yes but the kernel refused".
async fn exec_after_approval<W: AsyncWrite + Unpin>(
    request: ExecuteRequest,
    config: &ServerConfig,
    caller: &CallerIdentity,
    allow_reason: String,
    depth: u32,
    stream_output: bool,
    stream_writer: &mut W,
) -> ExecuteResult {
    if config.dry_run {
        tracing::info!(
            "Dry-run: not executing {} {:?} ({})",
            request.binary,
            request.args,
            caller
        );
        return ExecuteResult::dry_run(allow_reason);
    }

    let user_key = caller.user_key();
    let tool_env = {
        let mut reg = config.tool_registry.write().await;
        let _ = reg.reload_if_stale();
        reg.resolve_env(&request.binary, &config.secrets, user_key.as_deref())
            .await
    };
    let tool_env = match tool_env {
        Ok(env) => env,
        Err(e) => {
            return ExecuteResult::exec_failed(allow_reason, format!("tool config error: {}", e));
        }
    };

    tracing::info!(
        "Executing: {} {:?} ({})",
        request.binary,
        request.args,
        caller
    );

    let mut cmd = Command::new(&request.binary);
    cmd.args(&request.args);
    cmd.stdin(Stdio::null());

    // SECURITY: Clear ALL inherited env vars. The child process gets only what we
    // explicitly allow. This prevents leaking the guard's own secrets (API keys,
    // auth tokens) via env, printenv, /proc/self/environ, or $VAR expansion.
    cmd.env_clear();

    for var in &[
        "PATH",
        "HOME",
        "USER",
        "LANG",
        "LANGUAGE",
        "LC_ALL",
        "LC_CTYPE",
        "TERM",
        "TZ",
        "SHELL",
        "LOGNAME",
        "XDG_RUNTIME_DIR",
        "SSH_AUTH_SOCK",
    ] {
        if let Ok(val) = std::env::var(var) {
            cmd.env(var, val);
        }
    }

    for (key, value) in &tool_env {
        cmd.env(key, value);
    }

    cmd.env("GUARD_DEPTH", (depth + 1).to_string());

    if let Some(ref shim_dir) = config.shim_dir {
        let base_path = std::env::var("PATH").unwrap_or_default();
        cmd.env("PATH", format!("{}:{}", shim_dir.display(), base_path));
    }

    if stream_output {
        return execute_spawn_streaming(
            cmd,
            &request.binary,
            allow_reason,
            config,
            &tool_env,
            stream_writer,
        )
        .await;
    }

    let output = match cmd.output().await {
        Ok(o) => o,
        Err(e) => {
            return ExecuteResult::exec_failed(
                allow_reason,
                format!("failed to execute '{}': {}", request.binary, e),
            );
        }
    };

    let stdout = if output.stdout.is_empty() {
        None
    } else {
        let raw = &output.stdout[..output.stdout.len().min(MAX_OUTPUT_BYTES)];
        let s = String::from_utf8_lossy(raw).to_string();
        Some(redact_command_text(config, &tool_env, s))
    };

    let stderr = if output.stderr.is_empty() {
        None
    } else {
        let raw = &output.stderr[..output.stderr.len().min(MAX_OUTPUT_BYTES)];
        let s = String::from_utf8_lossy(raw).to_string();
        Some(redact_command_text(config, &tool_env, s))
    };

    ExecuteResult::completed(allow_reason, output.status.code(), stdout, stderr)
}

fn binary_exists_on_path(binary: &str) -> bool {
    let Some(path) = std::env::var_os("PATH") else {
        return false;
    };

    std::env::split_paths(&path).any(|dir| {
        let candidate = dir.join(binary);
        let Ok(metadata) = std::fs::metadata(candidate) else {
            return false;
        };
        metadata.is_file() && metadata.permissions().mode() & 0o111 != 0
    })
}

fn deterministic_credential_deny_reason(binary: &str, args: &[String]) -> Option<String> {
    let command = if args.is_empty() {
        binary.to_string()
    } else {
        format!("{} {}", binary, args.join(" "))
    };
    let lower = command.to_ascii_lowercase();
    let tokens = command_tokens(&lower);

    if lower.contains("/proc/") && lower.contains("/environ") {
        return Some(
            "credential preflight denied: /proc/*/environ can expose process secrets".to_string(),
        );
    }

    if tokens.iter().any(|token| token == "ps") && tokens.iter().any(|token| token == "eww") {
        return Some(
            "credential preflight denied: ps eww can expose process environments".to_string(),
        );
    }

    if tokens
        .iter()
        .any(|token| token == "env" || token == "printenv")
    {
        return Some(
            "credential preflight denied: environment dumps can expose credentials".to_string(),
        );
    }

    if lower.contains("/etc/default/guard")
        || lower.contains("/var/lib/guard/.ssh/")
        || lower.contains("/var/lib/guard/.kube/config")
        || lower.contains("/.ssh/id_")
        || lower.contains("~/.ssh/id_")
        || lower.contains("/.kube/config")
        || lower.contains("~/.kube/config")
        || lower.contains("/.aws/credentials")
        || lower.contains("~/.aws/credentials")
        || lower.contains("/.env")
        || tokens.iter().any(|token| token == ".env")
    {
        return Some(
            "credential preflight denied: command references credential material".to_string(),
        );
    }

    if has_token(&tokens, "kubectl")
        && has_token(&tokens, "config")
        && has_token(&tokens, "view")
        && has_token(&tokens, "--raw")
    {
        return Some("credential preflight denied: kubectl config view --raw can expose kubeconfig credentials".to_string());
    }

    if has_token(&tokens, "kubectl")
        && (has_token(&tokens, "secret")
            || has_token(&tokens, "secrets")
            || lower.contains("/secrets/")
            || lower.contains("/secrets?"))
    {
        return Some(
            "credential preflight denied: kubectl secret access can expose cluster credentials"
                .to_string(),
        );
    }

    if has_token(&tokens, "kubectl") && has_token(&tokens, "create") && has_token(&tokens, "token")
    {
        return Some(
            "credential preflight denied: kubectl create token emits credential material"
                .to_string(),
        );
    }

    None
}

fn has_token(tokens: &[String], needle: &str) -> bool {
    tokens.iter().any(|token| token == needle)
}

fn command_tokens(command: &str) -> Vec<String> {
    command
        .split(|c: char| {
            !(c.is_ascii_alphanumeric()
                || matches!(c, '-' | '_' | '.' | '/' | '~' | '*' | '?' | ':'))
        })
        .filter(|part| !part.is_empty())
        .map(str::to_string)
        .collect()
}

#[derive(Debug)]
struct StreamChunk {
    stream: OutputStream,
    data: String,
}

async fn execute_spawn_streaming<W: AsyncWrite + Unpin>(
    mut cmd: Command,
    binary: &str,
    allow_reason: String,
    config: &ServerConfig,
    tool_env: &HashMap<String, String>,
    writer: &mut W,
) -> ExecuteResult {
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    let mut child = match cmd.spawn() {
        Ok(child) => child,
        Err(e) => {
            return ExecuteResult::exec_failed(
                allow_reason,
                format!("failed to execute '{}': {}", binary, e),
            );
        }
    };

    let (tx, mut rx) = mpsc::channel::<StreamChunk>(32);
    let mut stream_tasks = Vec::new();

    if let Some(stdout) = child.stdout.take() {
        let tx = tx.clone();
        stream_tasks.push(tokio::spawn(async move {
            forward_stream_lines(stdout, OutputStream::Stdout, tx).await;
        }));
    }

    if let Some(stderr) = child.stderr.take() {
        let tx = tx.clone();
        stream_tasks.push(tokio::spawn(async move {
            forward_stream_lines(stderr, OutputStream::Stderr, tx).await;
        }));
    }

    drop(tx);

    let mut stdout_redaction = RedactionState::default();
    let mut stderr_redaction = RedactionState::default();
    let mut keepalive = tokio::time::interval(std::time::Duration::from_secs(1));
    loop {
        tokio::select! {
            maybe_chunk = rx.recv() => {
                match maybe_chunk {
                    Some(chunk) => {
                    let redaction_state = match chunk.stream {
                        OutputStream::Stdout => &mut stdout_redaction,
                        OutputStream::Stderr => &mut stderr_redaction,
                    };
                    let data = redact_command_text_with_state(config, tool_env, chunk.data, redaction_state);
                    let message = match chunk.stream {
                        OutputStream::Stdout => ExecuteStreamMessage::Stdout { data },
                        OutputStream::Stderr => ExecuteStreamMessage::Stderr { data },
                    };

                    if let Err(e) = write_stream_message(writer, &message).await {
                        let _ = child.kill().await;
                        return ExecuteResult::exec_failed(allow_reason, format!("client stream error: {}", e));
                    }
                    }
                    None => break,
                }
            }
            _ = keepalive.tick() => {
                if let Err(e) = write_stream_message(writer, &ExecuteStreamMessage::Keepalive).await {
                    let _ = child.kill().await;
                    return ExecuteResult::exec_failed(allow_reason, format!("client stream error: {}", e));
                }
            }
        }
    }

    for task in stream_tasks {
        let _ = task.await;
    }

    let status = match child.wait().await {
        Ok(status) => status,
        Err(e) => {
            return ExecuteResult::exec_failed(
                allow_reason,
                format!("failed to wait for '{}': {}", binary, e),
            );
        }
    };

    ExecuteResult::completed(allow_reason, status.code(), None, None)
}

async fn forward_stream_lines<R>(reader: R, stream: OutputStream, tx: mpsc::Sender<StreamChunk>)
where
    R: AsyncRead + Unpin,
{
    let mut reader = BufReader::new(reader);

    loop {
        let mut data = String::new();
        match reader.read_line(&mut data).await {
            Ok(0) => break,
            Ok(_) => {
                if tx.send(StreamChunk { stream, data }).await.is_err() {
                    break;
                }
            }
            Err(e) => {
                let _ = tx
                    .send(StreamChunk {
                        stream: OutputStream::Stderr,
                        data: format!("guard stream read error: {}\n", e),
                    })
                    .await;
                break;
            }
        }
    }
}

fn redact_command_text(
    config: &ServerConfig,
    tool_env: &HashMap<String, String>,
    text: String,
) -> String {
    redact_command_text_inner(config, tool_env, text, None)
}

fn redact_command_text_with_state(
    config: &ServerConfig,
    tool_env: &HashMap<String, String>,
    text: String,
    state: &mut RedactionState,
) -> String {
    redact_command_text_inner(config, tool_env, text, Some(state))
}

fn redact_command_text_inner(
    config: &ServerConfig,
    tool_env: &HashMap<String, String>,
    text: String,
    state: Option<&mut RedactionState>,
) -> String {
    if !config.redact {
        return text;
    }

    let secret_refs: Vec<&str> = config
        .redact_secrets
        .iter()
        .map(|s| s.as_str())
        .chain(tool_env.values().map(|s| s.as_str()))
        .collect();

    // First: exact-match redaction catches bare secret values in output.
    let text = redact_exact_secrets(&text, &secret_refs);
    // Then: regex and context-based redaction catches KEY=value, YAML env
    // pairs, PEM blocks, etc.
    if let Some(state) = state {
        let had_trailing_newline = text.ends_with('\n');
        let mut redacted = text
            .lines()
            .map(|line| redact_output_with_state(line, state))
            .collect::<Vec<_>>()
            .join("\n");
        if had_trailing_newline {
            redacted.push('\n');
        }
        redacted
    } else {
        redact_output_text(&text)
    }
}

pub struct Client {
    socket_path: Option<PathBuf>,
    tcp_port: Option<u16>,
    auth_token: Option<String>,
    session_token: Option<String>,
}

impl Client {
    pub fn new(socket_path: Option<PathBuf>, tcp_port: Option<u16>) -> Self {
        Self {
            socket_path,
            tcp_port,
            auth_token: None,
            session_token: None,
        }
    }

    pub fn with_auth(mut self, token: String) -> Self {
        self.auth_token = Some(token);
        self
    }

    pub fn with_session(mut self, session_token: String) -> Self {
        self.session_token = Some(session_token);
        self
    }

    pub fn auth_token_for_admin(&self) -> Option<String> {
        self.auth_token.clone()
    }

    pub async fn send_admin(&self, request: AdminRequest) -> Result<AdminResponse> {
        let envelope = IncomingMessage::Admin { admin: request };
        let line = serde_json::to_string(&envelope)?;

        if let Some(ref socket_path) = self.socket_path {
            let stream = UnixStream::connect(socket_path)
                .await
                .context("failed to connect to guard server")?;
            let (reader, writer) = stream.into_split();
            let mut writer = tokio::io::BufWriter::new(writer);
            writer.write_all(line.as_bytes()).await?;
            writer.write_all(b"\n").await?;
            writer.flush().await?;

            let mut lines = BufReader::new(reader).lines();
            let response_line = lines
                .next_line()
                .await?
                .ok_or_else(|| anyhow::anyhow!("server closed connection without response"))?;
            let resp: AdminResponse = serde_json::from_str(&response_line)
                .context("invalid admin server response")?;
            Ok(resp)
        } else if let Some(port) = self.tcp_port {
            let addr = format!("127.0.0.1:{}", port);
            let stream = tokio::net::TcpStream::connect(&addr)
                .await
                .context("failed to connect to guard server")?;
            let (reader, writer) = stream.into_split();
            let mut writer = tokio::io::BufWriter::new(writer);
            writer.write_all(line.as_bytes()).await?;
            writer.write_all(b"\n").await?;
            writer.flush().await?;

            let mut lines = BufReader::new(reader).lines();
            let response_line = lines
                .next_line()
                .await?
                .ok_or_else(|| anyhow::anyhow!("server closed connection without response"))?;
            let resp: AdminResponse = serde_json::from_str(&response_line)
                .context("invalid admin server response")?;
            Ok(resp)
        } else {
            anyhow::bail!("no socket path or TCP port configured");
        }
    }

    pub fn endpoint_for_log(&self) -> String {
        if let Some(ref socket_path) = self.socket_path {
            format!("unix:{}", socket_path.display())
        } else if let Some(port) = self.tcp_port {
            format!("tcp:127.0.0.1:{}", port)
        } else {
            "unconfigured".to_string()
        }
    }

    pub async fn execute(&self, binary: &str, args: &[String]) -> Result<ExecuteResponse> {
        let request = ExecuteRequest {
            binary: binary.to_string(),
            args: args.to_vec(),
            auth_token: self.auth_token.clone(),
            stream: false,
            session_token: self.session_token.clone(),
        };

        tracing::debug!(
            binary = %binary,
            arg_count = args.len(),
            endpoint = %self.endpoint_for_log(),
            "client dispatching execute request"
        );

        if let Some(ref socket_path) = self.socket_path {
            self.send_unix(socket_path, &request).await
        } else if let Some(port) = self.tcp_port {
            self.send_tcp(port, &request).await
        } else {
            anyhow::bail!("no socket path or TCP port configured");
        }
    }

    pub async fn execute_streaming<F>(
        &self,
        binary: &str,
        args: &[String],
        mut on_output: F,
    ) -> Result<ExecuteResponse>
    where
        F: FnMut(OutputStream, &str),
    {
        let request = ExecuteRequest {
            binary: binary.to_string(),
            args: args.to_vec(),
            auth_token: self.auth_token.clone(),
            stream: true,
            session_token: self.session_token.clone(),
        };

        tracing::debug!(
            binary = %binary,
            arg_count = args.len(),
            endpoint = %self.endpoint_for_log(),
            "client dispatching streaming execute request"
        );

        if let Some(ref socket_path) = self.socket_path {
            self.send_unix_streaming(socket_path, &request, &mut on_output)
                .await
        } else if let Some(port) = self.tcp_port {
            self.send_tcp_streaming(port, &request, &mut on_output)
                .await
        } else {
            anyhow::bail!("no socket path or TCP port configured");
        }
    }

    async fn send_unix(
        &self,
        socket_path: &PathBuf,
        request: &ExecuteRequest,
    ) -> Result<ExecuteResponse> {
        tracing::debug!(
            socket = %socket_path.display(),
            "connecting to guard server"
        );
        let stream = UnixStream::connect(socket_path)
            .await
            .context("failed to connect to guard server")?;
        tracing::debug!(
            socket = %socket_path.display(),
            "connected to guard server"
        );

        let (reader, writer) = stream.into_split();

        let mut writer = tokio::io::BufWriter::new(writer);
        tracing::debug!(
            binary = %request.binary,
            arg_count = request.args.len(),
            "sending execute request"
        );
        writer
            .write_all(serde_json::to_string(request)?.as_bytes())
            .await?;
        writer.write_all(b"\n").await?;
        writer.flush().await?;
        tracing::debug!("execute request sent; waiting for server response");

        let mut reader = BufReader::new(reader).lines();
        let Some(line) = reader.next_line().await? else {
            bail!("server closed connection without response");
        };

        let response: ExecuteResponse =
            serde_json::from_str(&line).context("invalid server response")?;
        tracing::debug!(
            allowed = response.allowed,
            exit_code = ?response.exit_code,
            has_stdout = response.stdout.is_some(),
            has_stderr = response.stderr.is_some(),
            "received execute response"
        );

        Ok(response)
    }

    async fn send_unix_streaming<F>(
        &self,
        socket_path: &PathBuf,
        request: &ExecuteRequest,
        on_output: &mut F,
    ) -> Result<ExecuteResponse>
    where
        F: FnMut(OutputStream, &str),
    {
        tracing::debug!(
            socket = %socket_path.display(),
            "connecting to guard server"
        );
        let stream = UnixStream::connect(socket_path)
            .await
            .context("failed to connect to guard server")?;
        tracing::debug!(
            socket = %socket_path.display(),
            "connected to guard server"
        );

        let (reader, writer) = stream.into_split();
        let mut writer = tokio::io::BufWriter::new(writer);
        tracing::debug!(
            binary = %request.binary,
            arg_count = request.args.len(),
            "sending streaming execute request"
        );
        writer
            .write_all(serde_json::to_string(request)?.as_bytes())
            .await?;
        writer.write_all(b"\n").await?;
        writer.flush().await?;
        tracing::debug!("streaming execute request sent; waiting for server response");

        let mut reader = BufReader::new(reader).lines();
        read_streaming_response(&mut reader, on_output).await
    }

    async fn send_tcp(&self, port: u16, request: &ExecuteRequest) -> Result<ExecuteResponse> {
        let addr = format!("127.0.0.1:{}", port);
        tracing::debug!(addr = %addr, "connecting to guard server");
        let stream = tokio::net::TcpStream::connect(&addr)
            .await
            .context("failed to connect to guard server")?;
        tracing::debug!(addr = %addr, "connected to guard server");

        let (reader, writer) = stream.into_split();

        let mut writer = tokio::io::BufWriter::new(writer);
        tracing::debug!(
            binary = %request.binary,
            arg_count = request.args.len(),
            "sending execute request"
        );
        writer
            .write_all(serde_json::to_string(request)?.as_bytes())
            .await?;
        writer.write_all(b"\n").await?;
        writer.flush().await?;
        tracing::debug!("execute request sent; waiting for server response");

        let mut reader = BufReader::new(reader).lines();
        let Some(line) = reader.next_line().await? else {
            bail!("server closed connection without response");
        };

        let response: ExecuteResponse =
            serde_json::from_str(&line).context("invalid server response")?;
        tracing::debug!(
            allowed = response.allowed,
            exit_code = ?response.exit_code,
            has_stdout = response.stdout.is_some(),
            has_stderr = response.stderr.is_some(),
            "received execute response"
        );

        Ok(response)
    }

    async fn send_tcp_streaming<F>(
        &self,
        port: u16,
        request: &ExecuteRequest,
        on_output: &mut F,
    ) -> Result<ExecuteResponse>
    where
        F: FnMut(OutputStream, &str),
    {
        let addr = format!("127.0.0.1:{}", port);
        tracing::debug!(addr = %addr, "connecting to guard server");
        let stream = tokio::net::TcpStream::connect(&addr)
            .await
            .context("failed to connect to guard server")?;
        tracing::debug!(addr = %addr, "connected to guard server");

        let (reader, writer) = stream.into_split();
        let mut writer = tokio::io::BufWriter::new(writer);
        tracing::debug!(
            binary = %request.binary,
            arg_count = request.args.len(),
            "sending streaming execute request"
        );
        writer
            .write_all(serde_json::to_string(request)?.as_bytes())
            .await?;
        writer.write_all(b"\n").await?;
        writer.flush().await?;
        tracing::debug!("streaming execute request sent; waiting for server response");

        let mut reader = BufReader::new(reader).lines();
        read_streaming_response(&mut reader, on_output).await
    }
}

async fn read_streaming_response<R, F>(
    reader: &mut tokio::io::Lines<BufReader<R>>,
    on_output: &mut F,
) -> Result<ExecuteResponse>
where
    R: AsyncRead + Unpin,
    F: FnMut(OutputStream, &str),
{
    let mut stdout = String::new();
    let mut stderr = String::new();

    while let Some(line) = reader.next_line().await? {
        match serde_json::from_str::<ExecuteStreamMessage>(&line) {
            Ok(ExecuteStreamMessage::Stdout { data }) => {
                on_output(OutputStream::Stdout, &data);
                stdout.push_str(&data);
            }
            Ok(ExecuteStreamMessage::Stderr { data }) => {
                on_output(OutputStream::Stderr, &data);
                stderr.push_str(&data);
            }
            Ok(ExecuteStreamMessage::PolicyDecision { allowed, reason }) => {
                if allowed {
                    tracing::info!(reason = %reason, "POLICY_ALLOWED");
                } else {
                    tracing::trace!(reason = %reason, "POLICY_DENIED");
                }
            }
            Ok(ExecuteStreamMessage::Keepalive) => {}
            Ok(ExecuteStreamMessage::Result { mut response }) => {
                if response.stdout.is_none() && !stdout.is_empty() {
                    response.stdout = Some(stdout);
                }
                if response.stderr.is_none() && !stderr.is_empty() {
                    response.stderr = Some(stderr);
                }
                tracing::debug!(
                    allowed = response.allowed,
                    exit_code = ?response.exit_code,
                    has_stdout = response.stdout.is_some(),
                    has_stderr = response.stderr.is_some(),
                    "received streaming execute response"
                );
                return Ok(response);
            }
            Err(_) => {
                let response: ExecuteResponse =
                    serde_json::from_str(&line).context("invalid server response")?;
                tracing::debug!(
                    allowed = response.allowed,
                    exit_code = ?response.exit_code,
                    has_stdout = response.stdout.is_some(),
                    has_stderr = response.stderr.is_some(),
                    "received non-streaming execute response"
                );
                return Ok(response);
            }
        }
    }

    bail!("server closed connection without response")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evaluate::{EvalConfig, Evaluator};
    use crate::secrets::{EnvBackend, SecretManager};
    use crate::tool_config::ToolRegistry;
    use std::io::Write;
    use std::sync::{Arc, Mutex};
    use tracing::subscriber::with_default;
    use tracing_subscriber::fmt::MakeWriter;

    // ---- ExecuteResult result-shape tests -----------------------------------

    #[test]
    fn execute_result_denied_has_denied_policy_and_not_attempted_exec() {
        let r = ExecuteResult::denied("nope");
        assert!(!r.policy_allowed());
        assert_eq!(r.policy_reason(), "nope");
        assert!(matches!(r.exec, ExecOutcome::NotAttempted));
    }

    #[test]
    fn execute_result_exec_failed_has_allowed_policy_and_failed_exec() {
        let r = ExecuteResult::exec_failed("looks fine", "no such file or directory");
        assert!(
            r.policy_allowed(),
            "exec_failed must still flag policy=allowed"
        );
        assert_eq!(r.policy_reason(), "looks fine");
        match &r.exec {
            ExecOutcome::Failed { reason } => {
                assert!(reason.contains("no such file"));
            }
            other => panic!("expected Failed, got {:?}", other),
        }
    }

    #[test]
    fn execute_result_completed_has_allowed_policy_and_completed_exec() {
        let r = ExecuteResult::completed(
            "static allow",
            Some(0),
            Some("out".into()),
            Some("err".into()),
        );
        assert!(r.policy_allowed());
        assert_eq!(r.policy_reason(), "static allow");
        match &r.exec {
            ExecOutcome::Completed {
                exit_code,
                stdout,
                stderr,
            } => {
                assert_eq!(*exit_code, Some(0));
                assert_eq!(stdout.as_deref(), Some("out"));
                assert_eq!(stderr.as_deref(), Some("err"));
            }
            other => panic!("expected Completed, got {:?}", other),
        }
    }

    #[test]
    fn binary_exists_on_path_rejects_natural_language_token() {
        assert!(!binary_exists_on_path(
            "Give-this-should-not-exist-as-a-real-command"
        ));
    }

    #[test]
    fn credential_preflight_denies_kubectl_raw_config_through_shell() {
        let args = vec![
            "-c".to_string(),
            "kubectl config view --raw >/dev/null && echo ok".to_string(),
        ];
        let reason = deterministic_credential_deny_reason("sh", &args)
            .expect("kubectl raw config should be denied");
        assert!(reason.contains("kubeconfig"));
    }

    #[test]
    fn credential_preflight_denies_private_key_path() {
        let args = vec![
            "-c".to_string(),
            "cat /var/lib/guard/.ssh/guard-admin >/dev/null".to_string(),
        ];
        let reason = deterministic_credential_deny_reason("sh", &args)
            .expect("guard private key path should be denied");
        assert!(reason.contains("credential material"));
    }

    #[test]
    fn credential_preflight_allows_basic_kubectl_inspection() {
        let args = vec!["get".to_string(), "namespaces".to_string()];
        assert!(deterministic_credential_deny_reason("kubectl", &args).is_none());
    }

    #[test]
    fn into_response_for_denied_sets_allowed_false() {
        let resp = ExecuteResult::denied("blocked").into_response();
        assert!(!resp.allowed);
        assert_eq!(resp.reason, "blocked");
        assert!(resp.exit_code.is_none());
    }

    #[test]
    fn into_response_for_exec_failed_sets_allowed_false_with_exec_error() {
        let resp = ExecuteResult::exec_failed("llm ok", "ENOENT").into_response();
        // Client-facing: the command did not run, so allowed=false is correct.
        // The audit log records POLICY=ALLOWED + EXEC_FAILED separately.
        assert!(!resp.allowed);
        assert!(resp.reason.contains("execution error"));
        assert!(resp.reason.contains("ENOENT"));
    }

    #[test]
    fn into_response_for_dry_run_sets_allowed_true_without_child_output() {
        let resp = ExecuteResult::dry_run("llm ok").into_response();
        assert!(resp.allowed);
        assert_eq!(resp.reason, "llm ok");
        assert_eq!(resp.exit_code, Some(0));
        assert_eq!(
            resp.stdout.as_deref(),
            Some("[DRY-RUN] policy allowed; command was not executed\n")
        );
        assert!(resp.stderr.is_none());
    }

    #[test]
    fn into_response_for_completed_carries_exit_and_streams() {
        let resp = ExecuteResult::completed("ok", Some(7), Some("hi".into()), None).into_response();
        assert!(resp.allowed);
        assert_eq!(resp.exit_code, Some(7));
        assert_eq!(resp.stdout.as_deref(), Some("hi"));
    }

    // ---- Audit emission end-to-end tests ------------------------------------

    /// Shared-buffer writer for the tracing fmt subscriber. Lets us capture
    /// emitted log lines and assert on their contents.
    #[derive(Clone)]
    struct SharedBuf(Arc<Mutex<Vec<u8>>>);

    impl Write for SharedBuf {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> MakeWriter<'a> for SharedBuf {
        type Writer = SharedBuf;
        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    fn make_test_config() -> (ServerConfig, SharedBuf) {
        // LLM disabled, no static policy → policy_allowed() never hits
        // this path; we manufacture results directly for audit tests.
        let eval_config = EvalConfig::default().llm_enabled(false);
        let evaluator = Evaluator::new(eval_config).expect("build evaluator");
        let secrets = SecretManager::with_backend(EnvBackend::default());
        let cfg = ServerConfig::new(
            None,
            None,
            evaluator,
            secrets,
            false,
            None,
            None,
            None,
            None,
            false,
            ToolRegistry::empty(),
            Vec::new(),
            false,
        );
        let buf = SharedBuf(Arc::new(Mutex::new(Vec::new())));
        (cfg, buf)
    }

    fn capture<F: FnOnce()>(buf: &SharedBuf, f: F) -> String {
        let subscriber = tracing_subscriber::fmt()
            .with_writer(buf.clone())
            .with_max_level(tracing::Level::INFO)
            .with_target(false)
            .with_ansi(false)
            .without_time()
            .finish();
        with_default(subscriber, f);
        let bytes = buf.0.lock().unwrap().clone();
        String::from_utf8_lossy(&bytes).to_string()
    }

    /// Policy denial: only the POLICY event fires, never EXEC_FAILED.
    /// Legacy grep patterns `[AUDIT] DENIED` still match.
    #[test]
    fn audit_policy_denied_emits_only_policy_event() {
        let (cfg, buf) = make_test_config();
        let caller = CallerIdentity::Unix { uid: 1000 };
        let result = ExecuteResult::denied("matched deny pattern: rm -rf /");

        let output = capture(&buf, || {
            emit_audit_events(&cfg, &caller, "rm", &["-rf".into(), "/".into()], &result);
        });

        assert!(
            output.contains("[AUDIT] DENIED"),
            "expected DENIED policy line, got: {output}"
        );
        assert!(
            !output.contains("EXEC_FAILED"),
            "policy denial must not produce EXEC_FAILED: {output}"
        );
    }

    /// Policy allows + exec fails: BOTH events fire. Legacy grep for
    /// `[AUDIT] ALLOWED` still matches, and tooling that wants exec-failure
    /// visibility can filter on EXEC_FAILED.
    #[test]
    fn audit_allowed_then_exec_failed_emits_both_events() {
        let (cfg, buf) = make_test_config();
        let caller = CallerIdentity::Unix { uid: 1000 };
        let result = ExecuteResult::exec_failed(
            "LLM approved: benign lookup",
            "failed to execute 'nonexistent-binary-xyz': No such file or directory",
        );

        let output = capture(&buf, || {
            emit_audit_events(&cfg, &caller, "nonexistent-binary-xyz", &[], &result);
        });

        assert!(
            output.contains("[AUDIT] ALLOWED"),
            "expected ALLOWED policy line (backward-compat format), got: {output}"
        );
        assert!(
            output.contains("[AUDIT] EXEC_FAILED"),
            "expected EXEC_FAILED line, got: {output}"
        );
        assert!(
            output.contains("nonexistent-binary-xyz"),
            "audit line should carry the binary name: {output}"
        );
        assert!(
            output.contains("No such file"),
            "EXEC_FAILED line should carry the exec error reason: {output}"
        );
    }

    /// Policy allows + exec succeeds: only the POLICY event fires.
    #[test]
    fn audit_allowed_and_completed_emits_only_policy_event() {
        let (cfg, buf) = make_test_config();
        let caller = CallerIdentity::Unix { uid: 42 };
        let result = ExecuteResult::completed("static allow", Some(0), None, None);

        let output = capture(&buf, || {
            emit_audit_events(&cfg, &caller, "echo", &["hi".into()], &result);
        });

        assert!(output.contains("[AUDIT] ALLOWED"));
        assert!(!output.contains("EXEC_FAILED"));
    }
}
