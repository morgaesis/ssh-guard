use clap::Parser;

fn get_version() -> &'static str {
    // If there's a git tag at HEAD, use just the tag (release build)
    if let Some(tag) = option_env!("SSH_GUARD_GIT_TAG") {
        return tag;
    }

    // Not on a tag - include commit hash and branch (dev build)
    let commit = option_env!("SSH_GUARD_GIT_COMMIT").unwrap_or("unknown");
    let branch = option_env!("SSH_GUARD_GIT_BRANCH").unwrap_or("unknown");

    // Return a static string by leaking the formatted string
    // This is safe because it only happens once at startup
    let version = format!("v{}-{} ({})", env!("CARGO_PKG_VERSION"), commit, branch);
    Box::leak(version.into_boxed_str())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Readonly,
    Paranoid,
    Safe,
}

impl std::str::FromStr for Mode {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "readonly" => Ok(Mode::Readonly),
            "paranoid" => Ok(Mode::Paranoid),
            "safe" => Ok(Mode::Safe),
            other => Err(format!(
                "unknown mode '{}'. Use: readonly, paranoid, safe",
                other
            )),
        }
    }
}

impl std::fmt::Display for Mode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Mode::Readonly => write!(f, "readonly"),
            Mode::Paranoid => write!(f, "paranoid"),
            Mode::Safe => write!(f, "safe"),
        }
    }
}

#[derive(Parser)]
#[command(name = "ssh-guard")]
#[command(about = "SSH wrapper that sends commands to an LLM for approval before execution")]
#[command(version = get_version())]
#[command(
    allow_hyphen_values = true,
    disable_help_flag = false,
    trailing_var_arg = true,
    after_help = "Examples:\n  ssh-guard user@host \"ls -la\"\n  ssh-guard -v user@host \"systemctl status nginx\"\n  ssh-guard --mode paranoid user@host \"cat /etc/passwd\"\n  ssh-guard --dry-run user@host \"rm -rf /tmp/*\""
)]
pub struct Cli {
    /// Increase verbosity (-v=info, -vv=debug, -vvv=trace, -vvvv=max trace)
    #[arg(short, long, action = clap::ArgAction::Count, global = true)]
    pub verbose: u8,

    /// Reduce output to errors only
    #[arg(short, long, global = true)]
    pub quiet: bool,

    /// Override policy mode (readonly, paranoid, safe)
    #[arg(short, long)]
    pub mode: Option<Mode>,

    /// Show what would happen without executing
    #[arg(long)]
    pub dry_run: bool,

    /// SSH arguments (passed through to ssh)
    #[arg(trailing_var_arg = true)]
    pub ssh_args: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mode_from_str() {
        assert_eq!("readonly".parse::<Mode>().unwrap(), Mode::Readonly);
        assert_eq!("paranoid".parse::<Mode>().unwrap(), Mode::Paranoid);
        assert_eq!("safe".parse::<Mode>().unwrap(), Mode::Safe);
        assert_eq!("READONLY".parse::<Mode>().unwrap(), Mode::Readonly);
        assert!("unknown".parse::<Mode>().is_err());
    }

    #[test]
    fn test_mode_display() {
        assert_eq!(Mode::Readonly.to_string(), "readonly");
        assert_eq!(Mode::Paranoid.to_string(), "paranoid");
        assert_eq!(Mode::Safe.to_string(), "safe");
    }

    #[test]
    fn test_cli_parse_basic() {
        let cli = Cli::try_parse_from(["ssh-guard", "user@host", "ls", "-la"]).unwrap();
        assert_eq!(cli.ssh_args, vec!["user@host", "ls", "-la"]);
        assert!(!cli.dry_run);
        assert!(!cli.quiet);
        assert_eq!(cli.verbose, 0);
        assert!(cli.mode.is_none());
    }

    #[test]
    fn test_cli_parse_with_options() {
        let cli = Cli::try_parse_from(["ssh-guard", "-vv", "--dry-run", "host", "uptime"]).unwrap();
        assert_eq!(cli.verbose, 2);
        assert!(cli.dry_run);
        assert_eq!(cli.ssh_args, vec!["host", "uptime"]);
    }

    #[test]
    fn test_cli_parse_mode_override() {
        let cli = Cli::try_parse_from(["ssh-guard", "--mode", "paranoid", "host", "ls"]).unwrap();
        assert_eq!(cli.mode, Some(Mode::Paranoid));
    }
}
