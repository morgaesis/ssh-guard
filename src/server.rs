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
use crate::redact::redact_output;
use crate::secrets::SecretManager;
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, UnixListener, UnixStream};
use tokio::process::Command;

const DEFAULT_SOCKET_PATH: &str = "/var/run/guard/guard.sock";
const DEFAULT_TCP_PORT: u16 = 8123;
const MAX_GUARD_DEPTH: u32 = 5;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecuteRequest {
    pub binary: String,
    pub args: Vec<String>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub env: HashMap<String, String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_token: Option<String>,
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
            let provided = token.unwrap_or("");
            if provided != *expected {
                anyhow::bail!("invalid auth token");
            }
        }
        Ok(())
    }

    fn log_connection(
        &self,
        uid: u32,
        token_name: &str,
        binary: &str,
        args: &[String],
        allowed: bool,
    ) {
        let action = if allowed { "ALLOWED" } else { "DENIED" };
        tracing::info!(
            "[{}] uid={} token={} cmd={} {} {}",
            action,
            uid,
            token_name,
            binary,
            args.join(" "),
            if allowed { "" } else { "- unauthorized" }
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
    ) -> Self {
        let config = ServerConfig {
            socket_path,
            tcp_port,
            evaluator: Arc::new(evaluator),
            secrets: Arc::new(secrets),
            redact,
            auth_token,
            socket_group,
            allowed_uids,
            shim_dir,
        };
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
        tracing::info!("handle_client_unix: received request: {}", line);
        let request: ExecuteRequest = match serde_json::from_str(&line) {
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

        if let Err(_e) = config.validate_token(request.auth_token.as_deref()) {
            config.log_connection(uid, "<invalid>", &request.binary, &request.args, false);
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

        let token_name = request.auth_token.as_deref().unwrap_or("<none>");
        let result = execute_command(request.clone(), config).await?;

        config.log_connection(
            uid,
            token_name,
            &request.binary,
            &request.args,
            result.allowed,
        );

        let resp = ExecuteResponse {
            allowed: result.allowed,
            reason: result.reason,
            exit_code: result.exit_code,
            stdout: result.stdout,
            stderr: result.stderr,
        };
        writer
            .write_all(serde_json::to_string(&resp)?.as_bytes())
            .await?;
        writer.write_all(b"\n").await?;
    }

    Ok(())
}

async fn handle_client_tcp(stream: tokio::net::TcpStream, config: &ServerConfig) -> Result<()> {
    let (reader, mut writer) = stream.into_split();
    let mut lines = BufReader::new(reader).lines();

    while let Ok(Some(line)) = lines.next_line().await {
        let request: ExecuteRequest = match serde_json::from_str(&line) {
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

        if let Err(_e) = config.validate_token(request.auth_token.as_deref()) {
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

        let token_name = request.auth_token.as_deref().unwrap_or("<none>");
        let result = execute_command(request.clone(), config).await?;

        config.log_connection(
            0,
            token_name,
            &request.binary,
            &request.args,
            result.allowed,
        );

        let resp = ExecuteResponse {
            allowed: result.allowed,
            reason: result.reason,
            exit_code: result.exit_code,
            stdout: result.stdout,
            stderr: result.stderr,
        };
        writer
            .write_all(serde_json::to_string(&resp)?.as_bytes())
            .await?;
        writer.write_all(b"\n").await?;
    }

    Ok(())
}

struct ExecuteResult {
    allowed: bool,
    reason: String,
    exit_code: Option<i32>,
    stdout: Option<String>,
    stderr: Option<String>,
}

async fn execute_command(request: ExecuteRequest, config: &ServerConfig) -> Result<ExecuteResult> {
    // Check recursion depth
    let depth: u32 = std::env::var("GUARD_DEPTH")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    if depth >= MAX_GUARD_DEPTH {
        return Ok(ExecuteResult {
            allowed: false,
            reason: format!("guard recursion depth exceeded (max {})", MAX_GUARD_DEPTH),
            exit_code: None,
            stdout: None,
            stderr: None,
        });
    }

    // Reconstruct full command line for policy evaluation
    let command_line = if request.args.is_empty() {
        request.binary.clone()
    } else {
        format!("{} {}", request.binary, request.args.join(" "))
    };

    let eval_result = config.evaluator.evaluate(&command_line).await;

    let allow_reason = match eval_result {
        crate::evaluate::EvalResult::Deny { reason, .. } => {
            return Ok(ExecuteResult {
                allowed: false,
                reason,
                exit_code: None,
                stdout: None,
                stderr: None,
            });
        }
        crate::evaluate::EvalResult::Error(e) => {
            tracing::error!("evaluation error: {}", e);
            return Ok(ExecuteResult {
                allowed: false,
                reason: format!("evaluation error: {}", e),
                exit_code: None,
                stdout: None,
                stderr: None,
            });
        }
        crate::evaluate::EvalResult::Allow { reason, .. } => {
            tracing::debug!("command allowed: {}", reason);
            reason
        }
    };

    tracing::info!("Executing: {} {:?}", request.binary, request.args);

    let mut cmd = Command::new(&request.binary);
    cmd.args(&request.args);
    cmd.stdin(Stdio::null());

    // Inject requested environment variables
    for (key, value) in &request.env {
        cmd.env(key, value);
    }

    // Set recursion depth for nested shim evaluation
    cmd.env("GUARD_DEPTH", (depth + 1).to_string());

    // Propagate shim directory in child PATH for nested evaluation
    if let Some(ref shim_dir) = config.shim_dir {
        let current_path = std::env::var("PATH").unwrap_or_default();
        cmd.env("PATH", format!("{}:{}", shim_dir.display(), current_path));
    }

    let output = cmd
        .output()
        .await
        .with_context(|| format!("failed to execute '{}'", request.binary))?;

    let stdout = if output.stdout.is_empty() {
        None
    } else {
        let s = String::from_utf8_lossy(&output.stdout).to_string();
        if config.redact {
            Some(s.lines().map(redact_output).collect::<Vec<_>>().join("\n"))
        } else {
            Some(s)
        }
    };

    let stderr = if output.stderr.is_empty() {
        None
    } else {
        let s = String::from_utf8_lossy(&output.stderr).to_string();
        if config.redact {
            Some(s.lines().map(redact_output).collect::<Vec<_>>().join("\n"))
        } else {
            Some(s)
        }
    };

    Ok(ExecuteResult {
        allowed: true,
        reason: allow_reason,
        exit_code: output.status.code(),
        stdout,
        stderr,
    })
}

pub struct Client {
    socket_path: Option<PathBuf>,
    tcp_port: Option<u16>,
    auth_token: Option<String>,
}

impl Client {
    pub fn new(socket_path: Option<PathBuf>, tcp_port: Option<u16>) -> Self {
        Self {
            socket_path,
            tcp_port,
            auth_token: None,
        }
    }

    pub fn with_auth(mut self, token: String) -> Self {
        self.auth_token = Some(token);
        self
    }

    pub async fn execute(&self, binary: &str, args: &[String]) -> Result<ExecuteResponse> {
        self.execute_with_env(binary, args, HashMap::new()).await
    }

    pub async fn execute_with_env(
        &self,
        binary: &str,
        args: &[String],
        env: HashMap<String, String>,
    ) -> Result<ExecuteResponse> {
        let request = ExecuteRequest {
            binary: binary.to_string(),
            args: args.to_vec(),
            env,
            auth_token: self.auth_token.clone(),
        };

        if let Some(ref socket_path) = self.socket_path {
            self.send_unix(socket_path, &request).await
        } else if let Some(port) = self.tcp_port {
            self.send_tcp(port, &request).await
        } else {
            anyhow::bail!("no socket path or TCP port configured");
        }
    }

    async fn send_unix(
        &self,
        socket_path: &PathBuf,
        request: &ExecuteRequest,
    ) -> Result<ExecuteResponse> {
        let stream = UnixStream::connect(socket_path)
            .await
            .context("failed to connect to guard server")?;

        let (reader, writer) = stream.into_split();

        let mut writer = tokio::io::BufWriter::new(writer);
        writer
            .write_all(serde_json::to_string(request)?.as_bytes())
            .await?;
        writer.write_all(b"\n").await?;
        writer.flush().await?;

        let mut reader = BufReader::new(reader).lines();
        let Some(line) = reader.next_line().await? else {
            bail!("server closed connection without response");
        };

        let response: ExecuteResponse =
            serde_json::from_str(&line).context("invalid server response")?;

        Ok(response)
    }

    async fn send_tcp(&self, port: u16, request: &ExecuteRequest) -> Result<ExecuteResponse> {
        let addr = format!("127.0.0.1:{}", port);
        let stream = tokio::net::TcpStream::connect(&addr)
            .await
            .context("failed to connect to guard server")?;

        let (reader, writer) = stream.into_split();

        let mut writer = tokio::io::BufWriter::new(writer);
        writer
            .write_all(serde_json::to_string(request)?.as_bytes())
            .await?;
        writer.write_all(b"\n").await?;
        writer.flush().await?;

        let mut reader = BufReader::new(reader).lines();
        let Some(line) = reader.next_line().await? else {
            bail!("server closed connection without response");
        };

        let response: ExecuteResponse =
            serde_json::from_str(&line).context("invalid server response")?;

        Ok(response)
    }
}
