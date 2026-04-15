//! guard - LLM-evaluated command gate for AI agents
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

use guard::evaluate;

use anyhow::{Context, Result};
use clap::{ArgAction, Parser, Subcommand};
use guard::policy::PolicyMode;
use std::path::PathBuf;
use tracing_subscriber::{fmt, EnvFilter};

#[derive(Parser)]
enum MainArgs {
    /// Execute a command through the guard server
    // `disable_help_flag` is critical: without it clap would intercept
    // `guard run df -h` and print the subcommand's own help instead of
    // forwarding `-h` to `df`. Users can still see the help for the `run`
    // subcommand via `guard help run`.
    #[clap(alias = "exec", disable_help_flag = true)]
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

fn parse_env_bool(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "on"
    )
}

#[derive(Subcommand)]
#[allow(clippy::large_enum_variant)]
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

        /// Retries per model on transient failures (default 2, capped at 2).
        /// Env: SSH_GUARD_LLM_RETRIES.
        #[arg(long)]
        llm_retries: Option<u32>,

        /// Ordered fallback chain of model slugs. If more than one is supplied,
        /// the evaluator tries them in order, each with its own retry budget.
        /// Overrides --llm-model when non-empty.
        /// Env: SSH_GUARD_LLM_MODELS (comma-separated).
        #[arg(long, value_delimiter = ',')]
        llm_models: Option<Vec<String>>,

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

        /// Disable output redaction (default: redaction enabled)
        #[arg(long = "no-redact", action = ArgAction::SetTrue)]
        no_redact: bool,

        /// Evaluate policy but do not execute approved commands.
        /// Env: SSH_GUARD_DRY_RUN.
        #[arg(long = "dry-run", action = ArgAction::SetTrue)]
        dry_run: bool,

        /// Path to custom system prompt file for the LLM evaluator
        #[arg(long)]
        system_prompt: Option<PathBuf>,

        /// Path to additive prompt file (appended to base prompt)
        #[arg(long)]
        system_prompt_append: Option<PathBuf>,
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
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
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

/// Try GUARD_ prefix, then SSH_GUARD_ prefix for a given env var suffix.
fn guard_env(suffix: &str) -> Option<String> {
    std::env::var(format!("GUARD_{}", suffix))
        .ok()
        .or_else(|| std::env::var(format!("SSH_GUARD_{}", suffix)).ok())
}

#[tokio::main]
async fn main() -> Result<()> {
    // Log level: RUST_LOG > GUARD_LOG_LEVEL > SSH_GUARD_LOG_LEVEL > "info"
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        let level = guard_env("LOG_LEVEL").unwrap_or_else(|| "warn".to_string());
        EnvFilter::new(level)
    });
    fmt().with_env_filter(filter).with_target(true).init();

    let args: Vec<String> = std::env::args().skip(1).collect();

    // Top-level --version / -V sniff. We cannot scan for --help / -h here
    // because `guard run df -h` must pass `-h` through to `df`. clap handles
    // `--help` natively on the top-level parser and every subcommand, so we
    // let it do its job for help output. We only keep the version sniff so
    // that `guard --version` stays concise and does not require parsing
    // subcommands.
    if top_level_version_requested(&args) {
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
            if e.kind() == clap::error::ErrorKind::DisplayHelp
                || e.kind() == clap::error::ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand
                || e.kind() == clap::error::ErrorKind::DisplayVersion =>
        {
            // Let clap render help/version to stdout and exit 0.
            e.exit();
        }
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

/// Returns true if the user asked for `--version` / `-V` at the top level,
/// before any subcommand. We scan only the very first positional token so
/// that `guard run foo -V` does not trigger a top-level version print.
fn top_level_version_requested(args: &[String]) -> bool {
    match args.first() {
        Some(first) => first == "--version" || first == "-V",
        None => false,
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
            llm_retries,
            llm_models,
            llm,
            no_llm,
            no_redact,
            dry_run,
            system_prompt,
            system_prompt_append,
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

            let dry_run = dry_run
                || guard_env("DRY_RUN")
                    .as_deref()
                    .map(parse_env_bool)
                    .unwrap_or(false);
            if dry_run {
                tracing::warn!("Dry-run mode enabled: approved commands will not be executed");
            }

            let llm_enabled = resolve_bool_flag(llm, no_llm, true);
            if !llm_enabled {
                tracing::info!("LLM evaluation disabled (static policy only)");
            }

            let api_key = llm_api_key
                .or_else(|| guard_env("LLM_API_KEY"))
                .or_else(|| std::env::var("OPENROUTER_API_KEY").ok())
                .or_else(|| guard_env("API_KEY")); // deprecated fallback

            if llm_enabled && api_key.is_none() {
                tracing::warn!("No LLM API key provided (set GUARD_LLM_API_KEY, OPENROUTER_API_KEY, or --llm-api-key)");
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

            // Model resolution precedence (single primary model):
            //   1. --llm-model CLI flag
            //   2. SSH_GUARD_LLM_MODEL env var (singular — primary model)
            //   3. evaluate::EvalConfig default (DEFAULT_MODEL in evaluate.rs)
            //
            // The fallback chain (SSH_GUARD_LLM_MODELS / --llm-models) is
            // resolved separately below and, when set, takes precedence over
            // the single-model value above because a chain is an explicit
            // opt-in to multi-model evaluation.
            let resolved_single_model = llm_model
                .filter(|value| !value.is_empty())
                .or_else(|| guard_env("LLM_MODEL").filter(|v| !v.is_empty()));
            if let Some(model) = resolved_single_model {
                eval_config = eval_config.llm_model(model);
            }

            // Retries: flag > env var > default.
            let retries = llm_retries
                .or_else(|| guard_env("LLM_RETRIES").and_then(|v| v.parse::<u32>().ok()))
                .unwrap_or(2);
            eval_config = eval_config.llm_retries(retries);
            tracing::info!("LLM retries per model: {}", retries);

            // Fallback chain: flag > env var > empty (no chain, single model).
            // When non-empty this supersedes the single-model value above.
            let models_chain: Vec<String> = llm_models
                .unwrap_or_default()
                .into_iter()
                .filter(|s| !s.is_empty())
                .collect::<Vec<_>>();
            let models_chain = if models_chain.is_empty() {
                guard_env("LLM_MODELS")
                    .map(|v| {
                        v.split(',')
                            .map(|s| s.trim().to_string())
                            .filter(|s| !s.is_empty())
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default()
            } else {
                models_chain
            };
            if !models_chain.is_empty() {
                tracing::info!("LLM model fallback chain: {:?}", models_chain);
                eval_config = eval_config.llm_models(models_chain);
            }

            let mode = guard_env("MODE")
                .and_then(|value| PolicyMode::parse(&value))
                .unwrap_or(PolicyMode::Readonly);

            tracing::info!("Using built-in {} policy mode", mode.as_str());
            eval_config = eval_config.mode(mode);

            if let Some(ref policy_path) = policy {
                tracing::info!("Loading static policy from: {}", policy_path);
                eval_config = eval_config.policy_path(PathBuf::from(policy_path));
            }

            if let Some(ref prompt_path) = system_prompt {
                tracing::info!("Loading system prompt from: {}", prompt_path.display());
                eval_config = eval_config.system_prompt_path(prompt_path.clone());
            }

            // Additive prompt: append to base prompt without replacing it.
            // Priority: --system-prompt-append flag > SSH_GUARD_PROMPT_APPEND env var
            let append_path = system_prompt_append.or_else(|| {
                guard_env("PROMPT_APPEND")
                    .filter(|v| !v.is_empty())
                    .map(PathBuf::from)
            });
            if let Some(ref path) = append_path {
                tracing::info!("Appending additive prompt from: {}", path.display());
                eval_config = eval_config.system_prompt_append_path(path.clone());
            }

            // Collect known secret values for exact-match output redaction BEFORE
            // moving eval_config into the evaluator.
            let mut redact_secrets: Vec<String> = Vec::new();
            if let Some(ref key) = eval_config.llm.api_key {
                if !key.is_empty() {
                    redact_secrets.push(key.clone());
                }
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

            // Redaction is server-side only, controlled by CLI flag.
            // NOT readable from child env (prevents SSH_GUARD_REDACT=false bypass).
            let redact = !no_redact;

            let tool_registry = tool_config::ToolRegistry::load_default().unwrap_or_else(|e| {
                tracing::warn!("Could not load tool config: {}", e);
                tool_config::ToolRegistry::empty()
            });
            let tool_count = tool_registry.list().count();
            if tool_count > 0 {
                tracing::info!("Loaded {} tool config(s)", tool_count);
            }
            if let Some(ref token) = auth_token {
                if !token.is_empty() {
                    redact_secrets.push(token.clone());
                }
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
                dry_run,
                tool_registry,
                redact_secrets,
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
        tracing::info!(
            binary = %binary,
            reason = %resp.reason,
            "ALLOWED"
        );
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
        tracing::warn!(
            binary = %binary,
            reason = %resp.reason,
            "DENIED"
        );
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
    // Surface load errors loudly for every subcommand — this catches the
    // relative-XDG_CONFIG_HOME case that previously fell through silently
    // and risked writing to the default path instead of the intended one.
    match subcommand {
        ConfigCommands::Show => {
            let config =
                client_config::ClientConfig::load().context("failed to load client config")?;
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
            let mut config =
                client_config::ClientConfig::load().context("failed to load client config")?;
            config.server_socket = Some(socket);
            config.server_tcp_port = None;
            config.save()?;
            println!("Server socket set");
        }
        ConfigCommands::SetPort { port } => {
            let mut config =
                client_config::ClientConfig::load().context("failed to load client config")?;
            config.server_tcp_port = Some(port);
            config.server_socket = None;
            config.save()?;
            println!("Server port set");
        }
        ConfigCommands::SetToken { token } => {
            let mut config =
                client_config::ClientConfig::load().context("failed to load client config")?;
            config.auth_token = Some(token);
            config.save()?;
            println!("Token set");
        }
        ConfigCommands::SetUser { user } => {
            let mut config =
                client_config::ClientConfig::load().context("failed to load client config")?;
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
                llm_retries,
                llm_models,
                llm,
                no_llm,
                no_redact,
                dry_run,
                system_prompt,
                system_prompt_append,
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
                llm_retries,
                llm_models,
                llm,
                no_llm,
                no_redact,
                dry_run,
                system_prompt,
                system_prompt_append,
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
        assert!(resolved_llm(&["guard", "server", "start"]));
    }

    #[test]
    fn test_server_start_llm_positive_forms() {
        assert!(resolved_llm(&["guard", "server", "start", "--llm"]));
        assert!(resolved_llm(&["guard", "server", "start", "--llm=true"]));
        assert!(resolved_llm(&["guard", "server", "start", "--llm", "true"]));
    }

    #[test]
    fn test_server_start_llm_negative_forms() {
        assert!(!resolved_llm(&["guard", "server", "start", "--no-llm"]));
        assert!(!resolved_llm(&["guard", "server", "start", "--llm=false"]));
        assert!(!resolved_llm(&[
            "guard", "server", "start", "--llm", "false"
        ]));
    }

    #[test]
    fn test_server_start_llm_retries_flag() {
        let ServerCommands::Start { llm_retries, .. } =
            parse_start(&["guard", "server", "start", "--llm-retries", "1"])
        else {
            panic!("expected start");
        };
        assert_eq!(llm_retries, Some(1));
    }

    /// Shared guard for tests that mutate `SSH_GUARD_LLM_MODEL*` environment
    /// variables. Rust's test runner executes tests in parallel by default,
    /// and `std::env::{set,remove}_var` mutates shared process state, so
    /// concurrent readers/writers must be serialized with a mutex.
    static MODEL_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Mirror of the resolution logic in `run_server` so we can exercise the
    /// precedence ladder without spinning up an actual server. Must stay in
    /// sync with the block under the "Model resolution precedence" comment
    /// in `run_server`.
    fn resolve_single_model_for_test(cli_flag: Option<String>) -> Option<String> {
        cli_flag.filter(|value| !value.is_empty()).or_else(|| {
            std::env::var("SSH_GUARD_LLM_MODEL")
                .ok()
                .filter(|v| !v.is_empty())
        })
    }

    fn resolve_chain_for_test(cli_flag: Option<Vec<String>>) -> Vec<String> {
        let models_chain: Vec<String> = cli_flag
            .unwrap_or_default()
            .into_iter()
            .filter(|s| !s.is_empty())
            .collect::<Vec<_>>();
        if models_chain.is_empty() {
            std::env::var("SSH_GUARD_LLM_MODELS")
                .ok()
                .map(|v| {
                    v.split(',')
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default()
        } else {
            models_chain
        }
    }

    /// Regression guard for silent-ignore of `SSH_GUARD_LLM_MODEL`. Exercises
    /// the full precedence ladder:
    ///
    ///   1. `--llm-model` CLI flag
    ///   2. `SSH_GUARD_LLM_MODEL` env var (singular)
    ///   3. default (`None` here; EvalConfig falls back to `DEFAULT_MODEL`)
    ///
    /// and verifies that `SSH_GUARD_LLM_MODELS` (plural, chain) still parses
    /// correctly alongside the singular. The test is sequential within a
    /// single function body because splitting into multiple `#[test]`
    /// functions would allow parallel process-env races even with a mutex
    /// (one test could observe another test's cleared state).
    #[test]
    fn test_llm_model_env_resolution_chain() {
        // SAFETY: serialize all process-env mutations in this test suite.
        let _guard = MODEL_ENV_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        // Snapshot existing values so we restore the shell's environment on
        // exit even if the harness inherited one of these vars.
        let prev_single = std::env::var("SSH_GUARD_LLM_MODEL").ok();
        let prev_chain = std::env::var("SSH_GUARD_LLM_MODELS").ok();

        // Env mutations are serialized across tests via MODEL_ENV_LOCK above.
        std::env::remove_var("SSH_GUARD_LLM_MODEL");
        std::env::remove_var("SSH_GUARD_LLM_MODELS");

        // 1. Clean slate: no flag, no env -> None (caller falls back to
        //    evaluate::DEFAULT_MODEL which is "openai/gpt-5.4-nano").
        assert_eq!(
            resolve_single_model_for_test(None),
            None,
            "with no flag and no env, single-model resolution must be None so \
             EvalConfig picks DEFAULT_MODEL"
        );
        assert_eq!(resolve_chain_for_test(None), Vec::<String>::new());

        // 2. SSH_GUARD_LLM_MODEL set -> picked up as primary.
        std::env::set_var("SSH_GUARD_LLM_MODEL", "alt/model-x");
        assert_eq!(
            resolve_single_model_for_test(None),
            Some("alt/model-x".to_string()),
            "SSH_GUARD_LLM_MODEL must be honored when no CLI flag is supplied"
        );

        // 3. CLI flag wins over the singular env var.
        assert_eq!(
            resolve_single_model_for_test(Some("flag/model-y".to_string())),
            Some("flag/model-y".to_string()),
            "--llm-model must take precedence over SSH_GUARD_LLM_MODEL"
        );

        // 4. Empty CLI flag falls through to env var.
        assert_eq!(
            resolve_single_model_for_test(Some(String::new())),
            Some("alt/model-x".to_string()),
            "empty --llm-model value must fall through to the env var"
        );

        // 5. Chain env var still parses independently of the singular var.
        std::env::set_var("SSH_GUARD_LLM_MODELS", "a,b,c");
        let chain = resolve_chain_for_test(None);
        assert_eq!(
            chain,
            vec!["a".to_string(), "b".to_string(), "c".to_string()],
            "SSH_GUARD_LLM_MODELS must parse into an ordered chain"
        );
        // The singular resolver is orthogonal and still returns the singular
        // value; the call site in run_server applies the precedence rule
        // ("chain wins when non-empty") when wiring EvalConfig.
        assert_eq!(
            resolve_single_model_for_test(None),
            Some("alt/model-x".to_string())
        );

        // Cleanup: restore prior values so other tests see the original env.
        match prev_single {
            Some(v) => std::env::set_var("SSH_GUARD_LLM_MODEL", v),
            None => std::env::remove_var("SSH_GUARD_LLM_MODEL"),
        }
        match prev_chain {
            Some(v) => std::env::set_var("SSH_GUARD_LLM_MODELS", v),
            None => std::env::remove_var("SSH_GUARD_LLM_MODELS"),
        }
    }

    #[test]
    fn test_server_start_llm_models_flag() {
        let ServerCommands::Start { llm_models, .. } = parse_start(&[
            "guard",
            "server",
            "start",
            "--llm-models",
            "openai/gpt-5.4-nano,meta-llama/llama-4-maverick",
        ]) else {
            panic!("expected start");
        };
        assert_eq!(
            llm_models,
            Some(vec![
                "openai/gpt-5.4-nano".to_string(),
                "meta-llama/llama-4-maverick".to_string()
            ])
        );
    }

    #[test]
    fn test_resolve_bool_flag() {
        assert!(resolve_bool_flag(None, false, true));
        assert!(!resolve_bool_flag(None, true, true));
        assert!(resolve_bool_flag(Some(true), false, false));
        assert!(!resolve_bool_flag(Some(false), false, true));
    }

    /// `guard run df -h` must forward `-h` to df. Earlier a pre-clap argv
    /// scan consumed `-h` before clap could see that it was a positional
    /// arg to the subcommand. We verify at the parser level: clap must
    /// parse `run echo -h` into the `Run` variant with `-h` in args.
    #[test]
    fn run_forwards_short_help_flag_to_child() {
        match MainArgs::try_parse_from(["guard", "run", "echo", "-h"]) {
            Ok(MainArgs::Run { binary, args }) => {
                assert_eq!(binary, "echo");
                assert_eq!(args, vec!["-h".to_string()]);
            }
            Ok(other) => panic!(
                "expected Run variant, got {:?}",
                std::mem::discriminant(&other)
            ),
            Err(e) => panic!("parser must not intercept -h: {}", e),
        }
    }

    /// Same story for `--help` — must be forwarded, not caught by clap's
    /// subcommand help handler.
    #[test]
    fn run_forwards_long_help_flag_to_child() {
        match MainArgs::try_parse_from(["guard", "run", "df", "--help"]) {
            Ok(MainArgs::Run { binary, args }) => {
                assert_eq!(binary, "df");
                assert_eq!(args, vec!["--help".to_string()]);
            }
            Ok(_) => panic!("expected Run variant"),
            Err(e) => panic!("parser must not intercept --help: {}", e),
        }
    }

    /// Mixed flags after the binary should all be forwarded intact.
    #[test]
    fn run_forwards_multiple_trailing_flags() {
        match MainArgs::try_parse_from(["guard", "run", "df", "-h", "/"]) {
            Ok(MainArgs::Run { binary, args }) => {
                assert_eq!(binary, "df");
                assert_eq!(args, vec!["-h".to_string(), "/".to_string()]);
            }
            Ok(_) => panic!("expected Run variant"),
            Err(e) => panic!("parser rejected valid run args: {}", e),
        }
    }

    #[test]
    fn server_connect_accepts_command_args_without_separator() {
        match MainArgs::try_parse_from([
            "guard",
            "server",
            "connect",
            "--socket",
            ".cache/guard.sock",
            "cp",
            "README.md",
            ".cache/copy",
        ]) {
            Ok(MainArgs::Server(ServerCommands::Connect {
                socket,
                binary,
                args,
                ..
            })) => {
                assert_eq!(socket, Some(".cache/guard.sock".to_string()));
                assert_eq!(binary, "cp");
                assert_eq!(
                    args,
                    vec!["README.md".to_string(), ".cache/copy".to_string()]
                );
            }
            Ok(_) => panic!("expected server connect variant"),
            Err(e) => panic!("parser rejected valid server connect args: {}", e),
        }
    }

    #[test]
    fn server_connect_forwards_hyphen_args_without_separator() {
        match MainArgs::try_parse_from([
            "guard",
            "server",
            "connect",
            "--socket",
            ".cache/guard.sock",
            "bash",
            "-lc",
            "id",
        ]) {
            Ok(MainArgs::Server(ServerCommands::Connect { binary, args, .. })) => {
                assert_eq!(binary, "bash");
                assert_eq!(args, vec!["-lc".to_string(), "id".to_string()]);
            }
            Ok(_) => panic!("expected server connect variant"),
            Err(e) => panic!("parser rejected valid server connect args: {}", e),
        }
    }

    /// Top-level `--help` must still work (clap handles it natively after
    /// we removed the argv pre-scan).
    #[test]
    fn top_level_help_still_triggers_clap_display_help() {
        match MainArgs::try_parse_from(["guard", "--help"]) {
            Ok(_) => panic!("expected clap to return DisplayHelp error"),
            Err(e) => assert_eq!(e.kind(), clap::error::ErrorKind::DisplayHelp),
        }
    }

    /// `guard help run` should show the subcommand help via clap. Note:
    /// because `Run` disables its own help flag, `guard run --help` would
    /// forward `--help` to the child instead — users get run help via
    /// `guard help run`. The instructions explicitly permit this tradeoff.
    #[test]
    fn help_run_shows_subcommand_help() {
        match MainArgs::try_parse_from(["guard", "help", "run"]) {
            Ok(_) => panic!("expected clap to return DisplayHelp for `help run`"),
            Err(e) => assert_eq!(e.kind(), clap::error::ErrorKind::DisplayHelp),
        }
    }

    #[test]
    fn top_level_version_requested_matches_first_arg_only() {
        assert!(top_level_version_requested(&["--version".to_string()]));
        assert!(top_level_version_requested(&["-V".to_string()]));
        assert!(!top_level_version_requested(&[
            "run".to_string(),
            "-V".to_string()
        ]));
        assert!(!top_level_version_requested(&[]));
    }
}
