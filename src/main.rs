//! Guard - policy-gated command execution for AI agents
//!
#![allow(unused)]

mod client_config;
mod mcp;
mod redact;
mod secrets;
mod server;
mod shim;
mod ssh;
mod tool_config;

use ssh_guard::evaluate;

use anyhow::{Context, Result};
use clap::{ArgAction, Parser, Subcommand};
use ssh_guard::policy::PolicyMode;
use std::path::PathBuf;
use tracing_subscriber::{fmt, EnvFilter};

#[derive(Parser)]
enum MainArgs {
    /// Execute a command through the guard server
    #[clap(alias = "exec")]
    Run {
        /// Binary to execute
        binary: String,
        /// Arguments to pass to the binary
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Server management
    #[clap(subcommand)]
    Server(ServerCommands),
    /// Manage secrets
    #[clap(subcommand)]
    Secrets(SecretCommands),
    /// Install shim scripts for command interposition
    Shim {
        /// Comma-separated list of tools to shim (e.g. ssh,kubectl,helm)
        #[arg(value_delimiter = ',')]
        tools: Option<Vec<String>>,
        /// List installed shims
        #[arg(long)]
        list: bool,
        /// Remove shims (all or specified tools)
        #[arg(long)]
        remove: bool,
        /// Custom shim directory
        #[arg(long)]
        path: Option<PathBuf>,
        /// Inject an environment variable (KEY=VALUE, repeatable)
        #[arg(long = "env", value_parser = parse_key_value)]
        env_vars: Vec<(String, String)>,
        /// Inject a secret as an env var (ENV_VAR=secret-name, repeatable)
        #[arg(long = "secret", value_parser = parse_key_value)]
        secret_vars: Vec<(String, String)>,
        /// Apply env/secret config to a specific user (UID or token name)
        #[arg(long)]
        user: Option<String>,
    },
    /// Manage client configuration
    #[clap(subcommand)]
    Config(ConfigCommands),
    /// Expose guard as an MCP server over stdio
    #[clap(subcommand)]
    Mcp(McpCommands),
}

fn parse_key_value(s: &str) -> Result<(String, String), String> {
    let pos = s
        .find('=')
        .ok_or_else(|| format!("expected KEY=VALUE, got '{s}'"))?;
    Ok((s[..pos].to_string(), s[pos + 1..].to_string()))
}

fn resolve_bool_flag(value: Option<bool>, negated: bool, default: bool) -> bool {
    if negated {
        false
    } else {
        value.unwrap_or(default)
    }
}

#[derive(Subcommand)]
enum ServerCommands {
    /// Start the guard server (privileged daemon)
    Start {
        #[arg(long)]
        socket: Option<String>,

        #[arg(long)]
        tcp_port: Option<u16>,

        #[arg(long)]
        auth_token: Option<String>,

        #[arg(long)]
        socket_group: Option<String>,

        #[arg(long)]
        users: Option<String>,

        #[arg(long)]
        policy: Option<String>,

        /// Shim directory for nested command evaluation
        #[arg(long)]
        shim_dir: Option<PathBuf>,

        #[arg(long)]
        llm_api_key: Option<String>,

        #[arg(long)]
        llm_api_url: Option<String>,

        #[arg(long)]
        llm_model: Option<String>,

        #[arg(long)]
        llm_timeout: Option<u64>,

        #[arg(
            long,
            action = ArgAction::Set,
            num_args = 0..=1,
            default_missing_value = "true",
            value_name = "BOOL",
            overrides_with = "no_llm"
        )]
        llm: Option<bool>,

        #[arg(long = "no-llm", action = ArgAction::SetTrue, overrides_with = "llm")]
        no_llm: bool,
    },
    /// Connect to guard server and execute a command
    Connect {
        #[arg(long)]
        socket: Option<String>,

        #[arg(long)]
        tcp_port: Option<u16>,

        #[arg(long)]
        token: Option<String>,

        /// Binary to execute
        binary: String,

        /// Arguments to pass to the binary
        #[arg(last = true)]
        args: Vec<String>,
    },
}

#[derive(Subcommand)]
enum ConfigCommands {
    /// Show current configuration
    Show,
    /// Set server socket path
    SetServer { socket: String },
    /// Set TCP port
    SetPort { port: u16 },
    /// Set auth token
    SetToken { token: String },
    /// Set default user
    SetUser { user: String },
    /// Clear configuration
    Clear,
}

#[derive(Subcommand)]
enum McpCommands {
    /// Start a stdio MCP server backed by the configured guard daemon
    Serve {
        #[arg(long)]
        socket: Option<String>,

        #[arg(long)]
        tcp_port: Option<u16>,

        #[arg(long)]
        token: Option<String>,

        #[arg(long, default_value = "guard_run")]
        tool_name: String,
    },
}

#[derive(Subcommand)]
enum SecretCommands {
    Add { key: String, value: Option<String> },
    List,
    Remove { key: String },
}

#[tokio::main]
async fn main() -> Result<()> {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    fmt().with_env_filter(filter).with_target(true).init();

    let args: Vec<String> = std::env::args().skip(1).collect();

    if args.iter().any(|a| a == "--help" || a == "-h") {
        match MainArgs::try_parse_from(std::env::args()) {
            Ok(_) => {}
            Err(e) => eprintln!("{}", e),
        }
        return Ok(());
    }

    if args.iter().any(|a| a == "--version" || a == "-V") {
        println!("guard v{}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }

    let result = MainArgs::try_parse_from(std::env::args());

    match result {
        Ok(MainArgs::Run { binary, args }) => run_exec(binary, args).await,
        Ok(MainArgs::Server(cmd)) => run_server(cmd).await,
        Ok(MainArgs::Secrets(subcommand)) => handle_secrets(subcommand).await,
        Ok(MainArgs::Shim {
            tools,
            list,
            remove,
            path,
            env_vars,
            secret_vars,
            user,
        }) => handle_shim(tools, list, remove, path, env_vars, secret_vars, user).await,
        Ok(MainArgs::Config(subcommand)) => handle_config(subcommand).await,
        Ok(MainArgs::Mcp(subcommand)) => run_mcp(subcommand).await,
        Err(ref e)
            if e.kind() == clap::error::ErrorKind::InvalidSubcommand
                || e.kind() == clap::error::ErrorKind::UnknownArgument =>
        {
            // Fallback: treat unknown subcommands as `run <binary> <args...>`
            if args.len() >= 2 && !args[0].starts_with('-') {
                let binary = args[0].clone();
                let cmd_args = args[1..].to_vec();
                run_exec(binary, cmd_args).await
            } else {
                eprintln!("{}", e);
                std::process::exit(1);
            }
        }
        Err(e) => {
            eprintln!("{}", e);
            std::process::exit(1);
        }
    }
}

async fn run_server(cmd: ServerCommands) -> Result<()> {
    match cmd {
        ServerCommands::Start {
            socket,
            tcp_port,
            auth_token,
            socket_group,
            users,
            policy,
            shim_dir,
            llm_api_key,
            llm_api_url,
            llm_model,
            llm_timeout,
            llm,
            no_llm,
        } => {
            tracing::info!("Starting guard server...");

            let socket_path = socket
                .map(PathBuf::from)
                .or_else(|| {
                    let config = client_config::ClientConfig::load().ok()?;
                    config.server_socket.map(PathBuf::from)
                })
                .or_else(|| dirs::home_dir().map(|h| h.join(".guard").join("guard.sock")));

            if let Some(ref path) = socket_path {
                tracing::info!("Socket: {}", path.display());
            }

            let shim_dir =
                shim_dir.or_else(|| dirs::home_dir().map(|h| h.join(".guard").join("shims")));

            if let Some(ref dir) = shim_dir {
                tracing::info!("Shim dir (nested evaluation): {}", dir.display());
            }

            let allowed_uids: Option<Vec<u32>> =
                users.map(|s| s.split(',').filter_map(|x| x.trim().parse().ok()).collect());
            tracing::info!("Allowed UIDs: {:?}", allowed_uids);

            let llm_enabled = resolve_bool_flag(llm, no_llm, true);
            if !llm_enabled {
                tracing::info!("LLM evaluation disabled (static policy only)");
            }

            let api_key = llm_api_key
                .or_else(|| std::env::var("OPENROUTER_API_KEY").ok())
                .or_else(|| std::env::var("SSH_GUARD_API_KEY").ok());

            if llm_enabled && api_key.is_none() {
                tracing::warn!("No LLM API key provided (set OPENROUTER_API_KEY or --llm-api-key)");
            }

            let mut eval_config = evaluate::EvalConfig::default()
                .llm_enabled(llm_enabled)
                .llm_timeout_secs(llm_timeout.unwrap_or(30));

            if let Some(api_key) = api_key.filter(|value| !value.is_empty()) {
                eval_config = eval_config.llm_api_key(api_key);
            }

            if let Some(api_url) = llm_api_url.filter(|value| !value.is_empty()) {
                eval_config = eval_config.llm_api_url(api_url);
            }

            if let Some(model) = llm_model.filter(|value| !value.is_empty()) {
                eval_config = eval_config.llm_model(model);
            }

            let mode = std::env::var("SSH_GUARD_MODE")
                .ok()
                .and_then(|value| PolicyMode::parse(&value));

            if let Some(mode) = mode {
                tracing::info!("Using built-in {} policy mode", mode.as_str());
                eval_config = eval_config.mode(mode);
            }

            if let Some(ref policy_path) = policy {
                tracing::info!("Loading static policy from: {}", policy_path);
                eval_config = eval_config.policy_path(PathBuf::from(policy_path));
            }

            tracing::info!("Creating evaluator...");
            let evaluator =
                evaluate::Evaluator::new(eval_config).context("Failed to create evaluator")?;
            tracing::info!("Evaluator created successfully");

            tracing::info!("Initializing secret backend...");
            let backend = secrets::detect_backend()
                .build()
                .context("Failed to create secret backend")?;
            let secrets = secrets::SecretManager::new(backend);
            tracing::info!("Secret backend ready");

            let redact = std::env::var("SSH_GUARD_REDACT")
                .map(|v| v != "false")
                .unwrap_or(true);

            let tool_registry = tool_config::ToolRegistry::load_default().unwrap_or_else(|e| {
                tracing::warn!("Could not load tool config: {}", e);
                tool_config::ToolRegistry::empty()
            });
            let tool_count = tool_registry.list().count();
            if tool_count > 0 {
                tracing::info!("Loaded {} tool config(s)", tool_count);
            }

            tracing::info!("Creating server instance...");
            let srv = server::Server::new(
                socket_path,
                tcp_port,
                evaluator,
                secrets,
                redact,
                auth_token,
                socket_group,
                allowed_uids,
                shim_dir,
                tool_registry,
            );
            srv.run().await
        }
        ServerCommands::Connect {
            socket,
            tcp_port,
            token,
            binary,
            args,
        } => {
            let socket_path = socket.map(PathBuf::from);
            let mut client = server::Client::new(socket_path, tcp_port);
            if let Some(token) = token {
                client = client.with_auth(token);
            }

            let resp = client.execute(&binary, &args).await?;

            if resp.allowed {
                if let Some(stdout) = &resp.stdout {
                    print!("{}", stdout);
                }
                if let Some(code) = resp.exit_code {
                    std::process::exit(code);
                }
                Ok(())
            } else {
                eprintln!("DENIED: {}", resp.reason);
                std::process::exit(1);
            }
        }
    }
}

async fn run_exec(binary: String, args: Vec<String>) -> Result<()> {
    let config = client_config::ClientConfig::load().ok().unwrap_or_default();

    let socket_path = config.server_socket.map(PathBuf::from);
    let tcp_port = config.server_tcp_port;

    if socket_path.is_none() && tcp_port.is_none() {
        eprintln!("No server configured");
        std::process::exit(1);
    }

    let mut client = server::Client::new(socket_path, tcp_port);
    if let Some(token) = config.auth_token {
        client = client.with_auth(token);
    }

    let resp = client.execute(&binary, &args).await?;

    if resp.allowed {
        if let Some(stdout) = &resp.stdout {
            print!("{}", stdout);
        }
        if let Some(stderr) = &resp.stderr {
            eprint!("{}", stderr);
        }
        if let Some(code) = resp.exit_code {
            std::process::exit(code);
        }
        Ok(())
    } else {
        eprintln!("DENIED: {}", resp.reason);
        std::process::exit(1);
    }
}

async fn run_mcp(subcommand: McpCommands) -> Result<()> {
    match subcommand {
        McpCommands::Serve {
            socket,
            tcp_port,
            token,
            tool_name,
        } => {
            let config = client_config::ClientConfig::load().ok().unwrap_or_default();
            let socket_path = socket.or(config.server_socket).map(PathBuf::from);
            let tcp_port = tcp_port.or(config.server_tcp_port);
            let auth_token = token.or(config.auth_token);

            let mcp_config = mcp::McpConfig {
                socket_path,
                tcp_port,
                auth_token,
                tool_name,
            };

            mcp::serve(mcp_config).await
        }
    }
}

async fn handle_config(subcommand: ConfigCommands) -> Result<()> {
    match subcommand {
        ConfigCommands::Show => {
            let config = client_config::ClientConfig::load().unwrap_or_default();
            println!("socket: {:?}", config.server_socket.unwrap_or_default());
            println!(
                "port: {:?}",
                config
                    .server_tcp_port
                    .map(|p| p.to_string())
                    .unwrap_or_default()
            );
            println!("user: {:?}", config.default_user.unwrap_or_default());
            println!(
                "token: {}",
                if config.auth_token.is_some() {
                    "***"
                } else {
                    "(none)"
                }
            );
        }
        ConfigCommands::SetServer { socket } => {
            let mut config = client_config::ClientConfig::load().unwrap_or_default();
            config.server_socket = Some(socket);
            config.server_tcp_port = None;
            config.save()?;
            println!("Server socket set");
        }
        ConfigCommands::SetPort { port } => {
            let mut config = client_config::ClientConfig::load().unwrap_or_default();
            config.server_tcp_port = Some(port);
            config.server_socket = None;
            config.save()?;
            println!("Server port set");
        }
        ConfigCommands::SetToken { token } => {
            let mut config = client_config::ClientConfig::load().unwrap_or_default();
            config.auth_token = Some(token);
            config.save()?;
            println!("Token set");
        }
        ConfigCommands::SetUser { user } => {
            let mut config = client_config::ClientConfig::load().unwrap_or_default();
            config.default_user = Some(user);
            config.save()?;
            println!("Default user set");
        }
        ConfigCommands::Clear => {
            let config = client_config::ClientConfig::default();
            config.save()?;
            println!("Configuration cleared");
        }
    }
    Ok(())
}

async fn handle_secrets(subcommand: SecretCommands) -> Result<()> {
    let backend = secrets::detect_backend()
        .build()
        .context("Failed to create secret backend")?;

    match subcommand {
        SecretCommands::Add { key, value } => {
            let secret_value = if let Some(v) = value {
                v
            } else {
                rpassword::prompt_password("Secret value: ")?
            };
            backend.set(&key, &secret_value).await?;
            println!("Secret '{}' stored", key);
            Ok(())
        }
        SecretCommands::List => {
            let keys = backend.list().await?;
            if keys.is_empty() {
                println!("No secrets stored");
            } else {
                for key in keys {
                    println!("  - {}", key);
                }
            }
            Ok(())
        }
        SecretCommands::Remove { key } => {
            backend.delete(&key).await?;
            println!("Secret '{}' removed", key);
            Ok(())
        }
    }
}

async fn handle_shim(
    tools: Option<Vec<String>>,
    list: bool,
    remove: bool,
    path: Option<PathBuf>,
    env_vars: Vec<(String, String)>,
    secret_vars: Vec<(String, String)>,
    user: Option<String>,
) -> Result<()> {
    let shim_dir = path.unwrap_or_else(|| {
        dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(".guard/shims")
    });

    if list {
        let generator = shim::ShimGenerator::new(std::env::current_exe()?, shim_dir);
        let installed = generator.list_installed()?;
        if installed.is_empty() {
            println!("No shims installed");
        } else {
            let registry = tool_config::ToolRegistry::load_default()
                .unwrap_or_else(|_| tool_config::ToolRegistry::empty());
            for s in installed {
                print!("  - {}", s);
                if let Some(tc) = registry.get(&s) {
                    let parts: Vec<String> = tc
                        .env
                        .iter()
                        .map(|(k, v)| format!("{k}={v}"))
                        .chain(tc.secrets.iter().map(|(k, v)| format!("{k}=<secret:{v}>")))
                        .collect();
                    if !parts.is_empty() {
                        print!("  [{}]", parts.join(", "));
                    }
                    for (uid, user_override) in &tc.users {
                        let user_parts: Vec<String> = user_override
                            .env
                            .iter()
                            .map(|(k, v)| format!("{k}={v}"))
                            .chain(
                                user_override
                                    .secrets
                                    .iter()
                                    .map(|(k, v)| format!("{k}=<secret:{v}>")),
                            )
                            .collect();
                        if !user_parts.is_empty() {
                            print!("  user({uid}): [{}]", user_parts.join(", "));
                        }
                    }
                }
                println!();
            }
        }
        return Ok(());
    }

    if remove {
        let generator = shim::ShimGenerator::new(std::env::current_exe()?, shim_dir);
        if let Some(tools) = tools {
            let tools_refs: Vec<&str> = tools.iter().map(|s| s.as_str()).collect();
            generator.remove(&tools_refs)?;
            // Also remove tool configs
            if let Ok(mut registry) = tool_config::ToolRegistry::load_default() {
                for t in &tools_refs {
                    let _ = registry.remove(t);
                }
            }
        } else {
            generator.remove_all()?;
        }
        println!("Removed shims");
        return Ok(());
    }

    // Default: install shims
    let tools_to_install = tools.unwrap_or_else(|| vec!["ssh".to_string(), "scp".to_string()]);
    let generator = shim::ShimGenerator::new(std::env::current_exe()?, shim_dir.clone());
    let tools_refs: Vec<&str> = tools_to_install.iter().map(|s| s.as_str()).collect();
    generator.generate(&tools_refs)?;
    println!("Installed shims to: {}", shim_dir.display());

    // Register tool configs if env/secret flags were provided
    if !env_vars.is_empty() || !secret_vars.is_empty() {
        let mut registry = tool_config::ToolRegistry::load_default()
            .unwrap_or_else(|_| tool_config::ToolRegistry::empty());

        for tool_name in &tools_to_install {
            let mut existing = registry.get(tool_name).cloned().unwrap_or_default();

            if let Some(ref user_key) = user {
                // Per-user override: store under users.<user_key>
                let user_override = existing.users.entry(user_key.clone()).or_default();

                for (k, v) in &env_vars {
                    user_override.env.insert(k.clone(), v.clone());
                }
                for (k, v) in &secret_vars {
                    user_override.secrets.insert(k.clone(), v.clone());
                }
                println!(
                    "Registered per-user ({}) config for: {}",
                    user_key, tool_name
                );
            } else {
                // Base tool config
                for (k, v) in &env_vars {
                    existing.env.insert(k.clone(), v.clone());
                }
                for (k, v) in &secret_vars {
                    existing.secrets.insert(k.clone(), v.clone());
                }
                println!("Registered tool config for: {}", tool_name);
            }

            registry.set(tool_name, existing)?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_start(args: &[&str]) -> ServerCommands {
        match MainArgs::parse_from(args) {
            MainArgs::Server(ServerCommands::Start {
                socket,
                tcp_port,
                auth_token,
                socket_group,
                users,
                policy,
                shim_dir,
                llm_api_key,
                llm_api_url,
                llm_model,
                llm_timeout,
                llm,
                no_llm,
            }) => ServerCommands::Start {
                socket,
                tcp_port,
                auth_token,
                socket_group,
                users,
                policy,
                shim_dir,
                llm_api_key,
                llm_api_url,
                llm_model,
                llm_timeout,
                llm,
                no_llm,
            },
            _ => panic!("expected server start args"),
        }
    }

    fn resolved_llm(args: &[&str]) -> bool {
        let ServerCommands::Start { llm, no_llm, .. } = parse_start(args) else {
            panic!("expected start");
        };

        resolve_bool_flag(llm, no_llm, true)
    }

    #[test]
    fn test_server_start_llm_defaults_true() {
        assert!(resolved_llm(&["ssh-guard", "server", "start"]));
    }

    #[test]
    fn test_server_start_llm_positive_forms() {
        assert!(resolved_llm(&["ssh-guard", "server", "start", "--llm"]));
        assert!(resolved_llm(&[
            "ssh-guard",
            "server",
            "start",
            "--llm=true"
        ]));
        assert!(resolved_llm(&[
            "ssh-guard",
            "server",
            "start",
            "--llm",
            "true"
        ]));
    }

    #[test]
    fn test_server_start_llm_negative_forms() {
        assert!(!resolved_llm(&["ssh-guard", "server", "start", "--no-llm"]));
        assert!(!resolved_llm(&[
            "ssh-guard",
            "server",
            "start",
            "--llm=false"
        ]));
        assert!(!resolved_llm(&[
            "ssh-guard",
            "server",
            "start",
            "--llm",
            "false"
        ]));
    }

    #[test]
    fn test_resolve_bool_flag() {
        assert!(resolve_bool_flag(None, false, true));
        assert!(!resolve_bool_flag(None, true, true));
        assert!(resolve_bool_flag(Some(true), false, false));
        assert!(!resolve_bool_flag(Some(false), false, true));
    }
}
