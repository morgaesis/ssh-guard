mod cli;
mod config;
mod llm;
mod prompts;
mod redact;
mod ssh;

use anyhow::Result;
use clap::Parser;
use cli::Cli;
use std::fs::OpenOptions;
use std::io::Write;
use std::process;

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let cli = Cli::parse();

    if let Err(e) = setup_logging(&cli) {
        eprintln!("ssh-guard: failed to initialize logging: {}", e);
        process::exit(1);
    }

    if let Err(e) = run(cli).await {
        eprintln!("ssh-guard: {}", e);
        process::exit(1);
    }
}

async fn run(cli: Cli) -> Result<()> {
    // Load .env files walking up from CWD
    config::load_env_files();

    // If no SSH args, pass through to ssh (will show usage)
    if cli.ssh_args.is_empty() {
        let config = config::load_config(cli.mode);
        // If config loading fails (no API key), still pass through for bare ssh
        let ssh_bin = config
            .map(|c| c.ssh_bin)
            .unwrap_or_else(|_| "/usr/bin/ssh".to_string());

        let status = tokio::process::Command::new(&ssh_bin).status().await?;
        process::exit(status.code().unwrap_or(1));
    }

    let remote_cmd = ssh::extract_command(&cli.ssh_args);
    let destination =
        ssh::extract_destination(&cli.ssh_args).unwrap_or_else(|| "unknown".to_string());

    // Block interactive sessions
    if remote_cmd.is_empty() {
        eprintln!("ssh-guard: interactive sessions are not permitted through ssh-guard.");
        eprintln!(
            "ssh-guard: provide a command: ssh-guard {} 'command'",
            destination
        );
        eprintln!("ssh-guard: for interactive access, use ssh directly.");
        log_to_file(
            None,
            &format!("BLOCKED interactive session attempt: {:?}", cli.ssh_args),
        );
        return Err(anyhow::anyhow!("interactive sessions are blocked"));
    }

    // Load config (requires API key for non-passthrough commands)
    let config = config::load_config(cli.mode)?;

    tracing::info!(
        "mode={} destination={} command={}",
        config.mode,
        destination,
        remote_cmd
    );

    log_to_file(
        config.log_file.as_deref(),
        &format!("REQUEST host={} cmd={}", destination, remote_cmd),
    );

    // Check passthrough
    if ssh::is_passthrough(&remote_cmd, &config.passthrough) {
        tracing::info!("passthrough match, executing directly");
        log_to_file(
            config.log_file.as_deref(),
            &format!("PASSTHROUGH cmd={}", remote_cmd),
        );

        if cli.dry_run {
            eprintln!(
                "ssh-guard: [dry-run] would execute (passthrough): ssh {:?}",
                cli.ssh_args
            );
            return Ok(());
        }

        let exit_code = ssh::exec_ssh(&config.ssh_bin, &cli.ssh_args, config.redact).await?;
        process::exit(exit_code);
    }

    // Resolve system prompt
    let system_prompt = prompts::resolve_prompt(config.mode, config.prompt_override.as_deref());

    tracing::trace!("system prompt: {}", system_prompt);
    tracing::debug!(
        "calling LLM: model={} api_type={:?} url={}",
        config.model,
        config.api_type,
        config.api_url
    );

    if cli.dry_run {
        eprintln!("ssh-guard: [dry-run] would call LLM for approval:");
        eprintln!("  host: {}", destination);
        eprintln!("  command: {}", remote_cmd);
        eprintln!("  mode: {}", config.mode);
        eprintln!("  model: {}", config.model);
        return Ok(());
    }

    // Call LLM
    let start = std::time::Instant::now();
    let decision = match llm::call_llm(&config, &system_prompt, &remote_cmd, &destination).await {
        Ok(d) => d,
        Err(e) => {
            // Fail closed
            let msg = format!("LLM call failed: {}", e);
            log_to_file(config.log_file.as_deref(), &format!("ERROR {}", msg));
            return Err(anyhow::anyhow!("{}", msg));
        }
    };
    let elapsed = start.elapsed();

    tracing::debug!(
        "LLM response in {:?}: decision={} risk={} reason={}",
        elapsed,
        decision.decision,
        decision.risk,
        decision.reason
    );

    if decision.is_approve() {
        // Silent on approve; log only when risk is notable (>= 4)
        if decision.risk >= 4 {
            log_to_file(
                config.log_file.as_deref(),
                &format!(
                    "APPROVED risk={} cmd={} reason={}",
                    decision.risk, remote_cmd, decision.reason
                ),
            );
        }

        let exit_code = ssh::exec_ssh(&config.ssh_bin, &cli.ssh_args, config.redact).await?;
        process::exit(exit_code);
    } else {
        log_to_file(
            config.log_file.as_deref(),
            &format!(
                "DENIED risk={} cmd={} reason={}",
                decision.risk, remote_cmd, decision.reason
            ),
        );
        eprintln!(
            "ssh-guard: DENIED (risk={}) - {}",
            decision.risk, decision.reason
        );
        process::exit(1);
    }
}

/// Append a timestamped line to the log file, if configured.
fn log_to_file(log_path: Option<&str>, message: &str) {
    let Some(path) = log_path else { return };

    let timestamp = chrono_lite_now();
    let line = format!("[{}] {}\n", timestamp, message);

    if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(path) {
        let _ = file.write_all(line.as_bytes());
    }
}

/// Simple ISO 8601-ish timestamp without pulling in chrono.
fn chrono_lite_now() -> String {
    use std::time::SystemTime;
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = now.as_secs();

    // Convert to a rough UTC timestamp string
    // Good enough for logging; not worth adding chrono as a dependency
    let days = secs / 86400;
    let time_of_day = secs % 86400;
    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;
    let seconds = time_of_day % 60;

    // Approximate year/month/day from days since epoch (1970-01-01)
    // Simple calculation, accurate enough for log timestamps
    let mut y = 1970i64;
    let mut remaining_days = days as i64;
    loop {
        let days_in_year = if is_leap_year(y) { 366 } else { 365 };
        if remaining_days < days_in_year {
            break;
        }
        remaining_days -= days_in_year;
        y += 1;
    }
    let days_in_months: [i64; 12] = if is_leap_year(y) {
        [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };
    let mut m = 0usize;
    for (i, &dim) in days_in_months.iter().enumerate() {
        if remaining_days < dim {
            m = i;
            break;
        }
        remaining_days -= dim;
    }

    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        y,
        m + 1,
        remaining_days + 1,
        hours,
        minutes,
        seconds
    )
}

fn is_leap_year(y: i64) -> bool {
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
}

fn setup_logging(cli: &Cli) -> Result<()> {
    use tracing_subscriber::{fmt, EnvFilter};

    let level = if cli.quiet {
        "error"
    } else {
        match cli.verbose {
            0 => "warn",
            1 => "info",
            2 => "debug",
            _ => "trace",
        }
    };

    let filter = EnvFilter::try_from_default_env()
        .or_else(|_| {
            let env_val = std::env::var("SSH_GUARD_LOG_LEVEL")
                .or_else(|_| std::env::var("LOG_LEVEL"))
                .unwrap_or_else(|_| level.to_string());
            EnvFilter::try_new(env_val)
        })
        .unwrap_or_else(|_| EnvFilter::new(level));

    fmt()
        .with_env_filter(filter)
        .with_target(false)
        .with_thread_ids(false)
        .with_thread_names(false)
        .init();

    Ok(())
}
