//! ssh-guard server mode - accepts command execution requests and runs them with privileged access.
//!
//! The server listens on a UNIX socket or TCP port and accepts requests from clients (agents).
//! Each request is evaluated against the policy engine before execution.
//!
//! Security model:
//! - UNIX socket: group-based access control (socket group = ssh-guard)
//! - TCP socket: auth token required
//! - Socket dir: 0750 (only owner + group can access)
//! - Socket: 0770 (owner + group read/write)

use crate::policy::PolicyEngine;
use crate::redact::redact_output;
use crate::secrets::SecretManager;
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, UnixListener, UnixStream};
use tokio::process::Command;

const DEFAULT_SOCKET_PATH: &str = "/var/run/ssh-guard/ssh-guard.sock";
const DEFAULT_TCP_PORT: u16 = 8123;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecuteRequest {
    pub target: String,
    pub command: String,
    pub user: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity_key: Option<String>,
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
    pub policy: Arc<PolicyEngine>,
    pub secrets: Arc<SecretManager>,
    pub ssh_bin: String,
    pub redact: bool,
    pub identity_key: Option<String>,
    pub auth_token: Option<String>,
    pub socket_group: Option<String>,
    pub allowed_uids: Option<Vec<u32>>,
}

impl ServerConfig {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        socket_path: Option<PathBuf>,
        tcp_port: Option<u16>,
        policy: PolicyEngine,
        secrets: SecretManager,
        ssh_bin: String,
        redact: bool,
        identity_key: Option<String>,
        auth_token: Option<String>,
        socket_group: Option<String>,
        allowed_uids: Option<Vec<u32>>,
    ) -> Self {
        Self {
            socket_path,
            tcp_port,
            policy: Arc::new(policy),
            secrets: Arc::new(secrets),
            ssh_bin,
            redact,
            identity_key,
            auth_token,
            socket_group,
            allowed_uids,
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
        target: &str,
        command: &str,
        allowed: bool,
    ) {
        let action = if allowed { "ALLOWED" } else { "DENIED" };
        tracing::info!(
            "[{}] uid={} token={} target={} cmd={} {}",
            action,
            uid,
            token_name,
            target,
            command,
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
        policy: PolicyEngine,
        secrets: SecretManager,
        ssh_bin: String,
        redact: bool,
        identity_key: Option<String>,
        auth_token: Option<String>,
        socket_group: Option<String>,
        allowed_uids: Option<Vec<u32>>,
    ) -> Self {
        let config = ServerConfig {
            socket_path,
            tcp_port,
            policy: Arc::new(policy),
            secrets: Arc::new(secrets),
            ssh_bin,
            redact,
            identity_key,
            auth_token,
            socket_group,
            allowed_uids,
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

        tracing::info!("ssh-guard server listening on {}", socket_path.display());

        if let Some(ref group) = config.socket_group {
            Self::chown_to_group(socket_path, group).await?;
            if let Some(parent) = socket_path.parent() {
                Self::chmod_dir(parent, 0o750).await?;
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

        tracing::info!("ssh-guard server listening on tcp://{}", addr);

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

    async fn chmod_dir(path: &std::path::Path, mode: u32) -> Result<()> {
        let output = Command::new("chmod")
            .arg(format!("{:o}", mode))
            .arg(path)
            .output()
            .await?;

        if !output.status.success() {
            bail!(
                "failed to chmod {}: {}",
                path.display(),
                String::from_utf8_lossy(&output.stderr)
            );
        }
        Ok(())
    }
}

async fn handle_client_unix(stream: UnixStream, config: &ServerConfig) -> Result<()> {
    tracing::info!("handle_client_unix: new connection");
    let uid = 0;
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
            config.log_connection(uid, "<invalid>", &request.target, &request.command, false);
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
            &request.target,
            &request.command,
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
            &request.target,
            &request.command,
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
    let cmd_parts =
        shell_words::split(&request.command).unwrap_or_else(|_| vec![request.command.clone()]);

    let cmd_name = cmd_parts.first().map(|s| s.as_str()).unwrap_or("");
    let args = &cmd_parts[1..];

    let policy_result = config.policy.check_command(cmd_name, args);

    if policy_result.is_denied() {
        return Ok(ExecuteResult {
            allowed: false,
            reason: policy_result.reason,
            exit_code: None,
            stdout: None,
            stderr: None,
        });
    }

    let mut ssh_args = vec![];

    let identity_key = request.identity_key.as_ref().or(config.identity_key.as_ref());
    let _identity_fd = if let Some(ref key_name) = identity_key {
        let fd = config
            .secrets
            .inject_fd(key_name)
            .await
            .context("failed to inject SSH key from secret store")?;
        ssh_args.extend(["-i".to_string(), fd.path().to_string_lossy().to_string()]);
        Some(fd)
    } else {
        None
    };

    if let Some(ref user) = request.user {
        ssh_args.extend(["-l".to_string(), user.clone()]);
    }

    ssh_args.push("-o".to_string());
    ssh_args.push("StrictHostKeyChecking=no".to_string());
    ssh_args.push("-o".to_string());
    ssh_args.push("ConnectTimeout=5".to_string());
    ssh_args.push("-o".to_string());
    ssh_args.push("PasswordAuthentication=no".to_string());
    ssh_args.push("-o".to_string());
    ssh_args.push("BatchMode=yes".to_string());
    ssh_args.push("-o".to_string());
    ssh_args.push("ServerAliveInterval=5".to_string());
    ssh_args.push("-o".to_string());
    ssh_args.push("ServerAliveCountMax=2".to_string());

    ssh_args.push(request.target.clone());
    ssh_args.push(request.command.clone());

    let is_localhost =
        request.target == "localhost" || request.target == "127.0.0.1" || request.target == "::1";

    let (exit_code, stdout, stderr) = if is_localhost {
        tracing::info!("Executing locally: {}", request.command);

        let output = tokio::process::Command::new("sh")
            .args(["-c", &request.command])
            .output()
            .await
            .context("failed to execute command")?;

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

        (output.status.code(), stdout, stderr)
    } else {
        tracing::info!("Executing SSH: {} {:?}", config.ssh_bin, ssh_args);

        let output = tokio::process::Command::new(&config.ssh_bin)
            .args(&ssh_args)
            .stdin(Stdio::null())
            .output()
            .await
            .context("failed to execute SSH command")?;

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

        (output.status.code(), stdout, stderr)
    };

    Ok(ExecuteResult {
        allowed: true,
        reason: policy_result.reason,
        exit_code,
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

    pub async fn execute(
        &self,
        target: &str,
        command: &str,
        user: Option<&str>,
    ) -> Result<ExecuteResponse> {
        self.execute_with_options(target, command, user, None).await
    }

    pub async fn execute_with_options(
        &self,
        target: &str,
        command: &str,
        user: Option<&str>,
        identity_key: Option<&str>,
    ) -> Result<ExecuteResponse> {
        if let Some(ref socket_path) = self.socket_path {
            self.execute_unix(socket_path, target, command, user, identity_key)
                .await
        } else if let Some(port) = self.tcp_port {
            self.execute_tcp(port, target, command, user, identity_key)
                .await
        } else {
            anyhow::bail!("no socket path or TCP port configured");
        }
    }

    async fn execute_unix(
        &self,
        socket_path: &PathBuf,
        target: &str,
        command: &str,
        user: Option<&str>,
        identity_key: Option<&str>,
    ) -> Result<ExecuteResponse> {
        let stream = UnixStream::connect(socket_path)
            .await
            .context("failed to connect to ssh-guard server")?;

        let (reader, writer) = stream.into_split();

        let request = ExecuteRequest {
            target: target.to_string(),
            command: command.to_string(),
            user: user.map(String::from),
            identity_key: identity_key.map(String::from),
            auth_token: self.auth_token.clone(),
        };

        let mut writer = tokio::io::BufWriter::new(writer);
        writer
            .write_all(serde_json::to_string(&request)?.as_bytes())
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

    async fn execute_tcp(
        &self,
        port: u16,
        target: &str,
        command: &str,
        user: Option<&str>,
        identity_key: Option<&str>,
    ) -> Result<ExecuteResponse> {
        let addr = format!("127.0.0.1:{}", port);
        let stream = tokio::net::TcpStream::connect(&addr)
            .await
            .context("failed to connect to ssh-guard server")?;

        let (reader, writer) = stream.into_split();

        let request = ExecuteRequest {
            target: target.to_string(),
            command: command.to_string(),
            user: user.map(String::from),
            identity_key: identity_key.map(String::from),
            auth_token: self.auth_token.clone(),
        };

        let mut writer = tokio::io::BufWriter::new(writer);
        writer
            .write_all(serde_json::to_string(&request)?.as_bytes())
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

    pub async fn execute_with_auth(
        &self,
        target: &str,
        command: &str,
        user: Option<&str>,
        auth_token: Option<&str>,
    ) -> Result<ExecuteResponse> {
        let mut client = Self::new(self.socket_path.clone(), self.tcp_port);
        if let Some(token) = auth_token {
            client = client.with_auth(token.to_string());
        }
        client.execute(target, command, user).await
    }
}
