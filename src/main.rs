//! ssh-guard server mode - privileged command execution guard for AI agents
//!
#![allow(unused)]

mod client_config;
mod redact;
mod secrets;
mod server;
mod shim;
mod ssh;

use ssh_guard::evaluate;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use tracing_subscriber::{fmt, EnvFilter};

#[derive(Parser)]
enum MainArgs {
    /// Connect to ssh-guard server and execute command
    #[clap(alias = "exec")]
    Run {
        #[arg(short = 'i')]
        identity: Option<String>,
        #[arg(short = 'u')]
        user: Option<String>,
        target: String,
        command: Vec<String>,
    },
    /// Server management
    #[clap(subcommand)]
    Server(ServerCommands),
    /// Manage secrets
    #[clap(subcommand)]
    Secrets(SecretCommands),
    /// Install shim scripts
    #[clap(subcommand)]
    Shim(ShimCommands),
    /// Manage client configuration
    #[clap(subcommand)]
    Config(ConfigCommands),
}

#[derive(Subcommand)]
enum ServerCommands {
    /// Start the ssh-guard server (privileged daemon)
    Start {
        #[arg(long)]
        socket: Option<String>,

        #[arg(long)]
        tcp_port: Option<u16>,

        #[arg(long, default_value = "/usr/bin/ssh")]
        ssh_bin: Option<String>,

        #[arg(long)]
        identity_key: Option<String>,

        #[arg(long)]
        auth_token: Option<String>,

        #[arg(long)]
        socket_group: Option<String>,

        #[arg(long)]
        users: Option<String>,

        #[arg(long)]
        policy: Option<String>,

        #[arg(long)]
        llm_api_key: Option<String>,

        #[arg(long)]
        llm_api_url: Option<String>,

        #[arg(long)]
        llm_model: Option<String>,

        #[arg(long)]
        llm_timeout: Option<u64>,

        #[arg(long)]
        no_llm: bool,
    },
    /// Connect to ssh-guard server
    Connect {
        #[arg(long)]
        socket: Option<String>,

        #[arg(long)]
        tcp_port: Option<u16>,

        #[arg(long)]
        token: Option<String>,

        target: String,

        #[arg(last = true)]
        command: Vec<String>,
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
enum ShimCommands {
    Install {
        #[arg(long)]
        path: Option<PathBuf>,
        #[arg(long, value_delimiter = ',')]
        tools: Option<Vec<String>>,
    },
    Remove {
        #[arg(long)]
        path: Option<PathBuf>,
    },
    List {
        #[arg(long)]
        path: Option<PathBuf>,
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
        println!("ssh-guard v{}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }

    let result = MainArgs::try_parse_from(std::env::args());

    match result {
        Ok(MainArgs::Run {
            identity,
            user,
            target,
            command,
        }) => run_connect(identity, user, target, command).await,
        Ok(MainArgs::Server(cmd)) => run_server(cmd).await,
        Ok(MainArgs::Secrets(subcommand)) => handle_secrets(subcommand).await,
        Ok(MainArgs::Shim(subcommand)) => handle_shim(subcommand).await,
        Ok(MainArgs::Config(subcommand)) => handle_config(subcommand).await,
        Err(ref e)
            if e.kind() == clap::error::ErrorKind::InvalidSubcommand
                || e.kind() == clap::error::ErrorKind::UnknownArgument =>
        {
            if let Some(run_args) = parse_as_run(&args) {
                run_connect(
                    run_args.identity,
                    run_args.user,
                    run_args.target,
                    run_args.command,
                )
                .await
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

struct RunArgs {
    identity: Option<String>,
    user: Option<String>,
    target: String,
    command: Vec<String>,
}

fn parse_as_run(args: &[String]) -> Option<RunArgs> {
    if args.is_empty() {
        return None;
    }

    let mut identity = None;
    let mut user = None;
    let mut target = None;
    let mut command = Vec::new();
    let mut collecting_command = false;

    let mut iter = args.iter().peekable();
    while let Some(arg) = iter.next() {
        if collecting_command {
            command.push(arg.clone());
        } else if arg == "-i" {
            identity = iter.next().cloned();
        } else if arg == "-u" {
            user = iter.next().cloned();
        } else if arg == "--" {
            collecting_command = true;
        } else if !arg.starts_with('-') {
            target = Some(arg.clone());
            collecting_command = true;
            for remaining in iter {
                command.push(remaining.clone());
            }
            break;
        }
    }

    let target = target?;
    if command.is_empty() {
        return None;
    }

    Some(RunArgs {
        identity,
        user,
        target,
        command,
    })
}

async fn run_server(cmd: ServerCommands) -> Result<()> {
    match cmd {
        ServerCommands::Start {
            socket,
            tcp_port,
            ssh_bin,
            identity_key,
            auth_token,
            socket_group,
            users,
            policy,
            llm_api_key,
            llm_api_url,
            llm_model,
            llm_timeout,
            no_llm,
        } => {
            tracing::info!("Starting ssh-guard server...");

            let socket_path = socket
                .map(PathBuf::from)
                .or_else(|| {
                    let config = client_config::ClientConfig::load().ok()?;
                    config.server_socket.map(PathBuf::from)
                })
                .or_else(|| dirs::home_dir().map(|h| h.join(".guard").join("guard.sock")));

            let ssh_binary = ssh_bin.unwrap_or_else(|| "/usr/bin/ssh".to_string());
            tracing::info!("SSH binary: {}", ssh_binary);

            if let Some(ref path) = socket_path {
                tracing::info!("Socket: {}", path.display());
            }

            let allowed_uids: Option<Vec<u32>> =
                users.map(|s| s.split(',').filter_map(|x| x.trim().parse().ok()).collect());
            tracing::info!("Allowed UIDs: {:?}", allowed_uids);

            let llm_enabled = !no_llm;
            if no_llm {
                tracing::info!("LLM evaluation disabled (static policy only)");
            }

            let api_key = llm_api_key
                .or_else(|| std::env::var("OPENROUTER_API_KEY").ok())
                .or_else(|| std::env::var("SSH_GUARD_API_KEY").ok());

            if llm_enabled && api_key.is_none() {
                tracing::warn!("No LLM API key provided (set OPENROUTER_API_KEY or --llm-api-key)");
            }

            let eval_config = evaluate::EvalConfig::default()
                .llm_enabled(llm_enabled)
                .llm_api_key(api_key.unwrap_or_default())
                .llm_api_url(llm_api_url.unwrap_or_default())
                .llm_model(llm_model.unwrap_or_default())
                .llm_timeout_secs(llm_timeout.unwrap_or(30));

            if let Some(ref policy_path) = policy {
                tracing::info!("Loading static policy from: {}", policy_path);
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

            tracing::info!("Creating server instance...");
            let srv = server::Server::new(
                socket_path,
                tcp_port,
                evaluator,
                secrets,
                ssh_binary,
                redact,
                identity_key,
                auth_token,
                socket_group,
                allowed_uids,
            );
            srv.run().await
        }
        ServerCommands::Connect {
            socket,
            tcp_port,
            token,
            target,
            command,
        } => {
            let socket_path = socket.map(PathBuf::from);
            let client = server::Client::new(socket_path, tcp_port);

            let user = std::env::var("USER").ok();
            let cmd_str = command.join(" ");

            let resp = client
                .execute_with_auth(&target, &cmd_str, user.as_deref(), token.as_deref())
                .await?;

            if resp.allowed {
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

async fn run_connect(
    identity: Option<String>,
    user: Option<String>,
    target: String,
    command: Vec<String>,
) -> Result<()> {
    let config = client_config::ClientConfig::load().ok().unwrap_or_default();
    let cmd_str = command.join(" ");

    let user = config
        .default_user
        .clone()
        .or(user)
        .or_else(|| std::env::var("USER").ok());

    if let Some(ref socket) = config.server_socket {
        let socket_path = PathBuf::from(socket);
        let client = server::Client::new(Some(socket_path.clone()), config.server_tcp_port);
        let resp = client
            .execute_with_options(&target, &cmd_str, user.as_deref(), identity.as_deref())
            .await?;

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
    } else if let Some(port) = config.server_tcp_port {
        let client = server::Client::new(None, Some(port));
        let resp = client
            .execute_with_options(&target, &cmd_str, user.as_deref(), identity.as_deref())
            .await?;

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
    } else {
        eprintln!("No server configured");
        std::process::exit(1);
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

async fn handle_shim(subcommand: ShimCommands) -> Result<()> {
    let shim_dir = dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".guard/shims");

    match subcommand {
        ShimCommands::Install { path, tools } => {
            let target_dir = path.unwrap_or(shim_dir);
            let tools_to_install =
                tools.unwrap_or_else(|| vec!["ssh".to_string(), "scp".to_string()]);
            let generator = shim::ShimGenerator::with_defaults()?;
            let tools_refs: Vec<&str> = tools_to_install.iter().map(|s| s.as_str()).collect();
            generator.generate(&tools_refs)?;
            println!("Installed shims to: {}", target_dir.display());
            Ok(())
        }
        ShimCommands::Remove { path } => {
            let target_dir = path.unwrap_or(shim_dir);
            let generator = shim::ShimGenerator::new(std::env::current_exe()?, target_dir);
            generator.remove_all()?;
            println!("Removed shims");
            Ok(())
        }
        ShimCommands::List { path } => {
            let target_dir = path.unwrap_or(shim_dir);
            let generator = shim::ShimGenerator::new(std::env::current_exe()?, target_dir);
            let installed = generator.list_installed()?;
            if installed.is_empty() {
                println!("No shims installed");
            } else {
                for shim in installed {
                    println!("  - {}", shim);
                }
            }
            Ok(())
        }
    }
}
