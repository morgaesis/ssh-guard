//! Git hook integration for secret scanning.
//!
//! This module provides functionality to:
//! - Install pre-commit and pre-push hooks that scan for secrets
//! - Scan staged files for secrets before commit
//! - Scan all files in a commit before push
//!
//! # Installation
//!
//! ```rust,no_run
//! use std::path::Path;
//! use ssh_guard::git_hook::{install_hook, HookType};
//!
//! // Install both hooks
//! let repo = Path::new("/path/to/repo");
//! install_hook(repo, HookType::PreCommit).await?;
//! install_hook(repo, HookType::PrePush).await?;
//! ```
//!
//! # Manual usage
//!
//! ```bash
//! guard git-hook install --path /repo/path --hook pre-commit
//! guard git-hook scan --staged
//! guard git-hook scan --commit abc123
//! ```

use anyhow::{bail, Context, Result};
use std::fs::{self, File};
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::env;

use tokio::process::Command as AsyncCommand;

use crate::redact::Redactor;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Type of git hook to install.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum HookType {
    /// Runs before a commit is created.
    PreCommit,
    /// Runs before a push is sent to a remote.
    PrePush,
}

impl HookType {
    /// Return the filename for this hook type.
    pub fn filename(&self) -> &'static str {
        match self {
            HookType::PreCommit => "pre-commit",
            HookType::PrePush => "pre-push",
        }
    }

    /// Return the CLI name for this hook type.
    pub fn cli_name(&self) -> &'static str {
        match self {
            HookType::PreCommit => "pre-commit",
            HookType::PrePush => "pre-push",
        }
    }
}

impl std::str::FromStr for HookType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "pre-commit" | "precommit" => Ok(HookType::PreCommit),
            "pre-push" | "prepush" => Ok(HookType::PrePush),
            other => Err(format!(
                "unknown hook type '{}'. Use: pre-commit, pre-push",
                other
            )),
        }
    }
}

impl std::fmt::Display for HookType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.cli_name())
    }
}

/// Represents a detected secret in a file.
#[derive(Debug, Clone)]
pub struct SecretFinding {
    /// Path to the file containing the secret (relative to repo root).
    pub file: PathBuf,
    /// Line number where the secret was detected (1-indexed).
    pub line: usize,
    /// The secret type detected (e.g., "AWS Key", "sk- key", "password").
    pub secret_type: String,
    /// The matched text (redacted in output).
    pub matched_text: String,
    /// The full line content (redacted).
    pub line_content: String,
}

impl SecretFinding {
    /// Create a new finding with redacted matched text.
    fn new(file: PathBuf, line: usize, secret_type: String, matched_text: &str) -> Self {
        let redacted = Redactor::new().redact(matched_text);
        Self {
            file,
            line,
            secret_type,
            matched_text: redacted,
            line_content: String::new(), // Set separately
        }
    }
}

/// Result of a scan operation.
#[derive(Debug, Clone)]
pub struct ScanResult {
    /// All findings across all files.
    pub findings: Vec<SecretFinding>,
    /// Total files scanned.
    pub files_scanned: usize,
    /// Files that could not be scanned (binary, etc.).
    pub skipped_files: Vec<PathBuf>,
}

impl ScanResult {
    /// Return true if any secrets were found.
    pub fn has_secrets(&self) -> bool {
        !self.findings.is_empty()
    }

    /// Return the total number of secrets found.
    pub fn secret_count(&self) -> usize {
        self.findings.len()
    }
}

// ---------------------------------------------------------------------------
// Hook Installation
// ---------------------------------------------------------------------------

/// Install a git hook into a repository.
///
/// Creates or overwrites the hook script at `.git/hooks/{hook_type}`.
/// The hook script calls back to `guard git-hook scan` to detect secrets.
pub async fn install_hook(repo_path: &Path, hook_type: HookType) -> Result<()> {
    validate_repo_path(repo_path).context("hook installation requires a valid git repository")?;

    let hooks_dir = repo_path.join(".git").join("hooks");
    let hook_path = hooks_dir.join(hook_type.filename());

    // Create hooks directory if it doesn't exist
    if !hooks_dir.exists() {
        fs::create_dir_all(&hooks_dir)
            .context(format!("failed to create hooks directory: {}", hooks_dir.display()))?;
    }

    let hook_content = render_hook_script(hook_type);

    // Write the hook script
    let mut file = File::create(&hook_path)
        .context(format!("failed to create hook: {}", hook_path.display()))?;

    file.write_all(hook_content.as_bytes())
        .context(format!("failed to write hook: {}", hook_path.display()))?;

    // Make executable
    let metadata = fs::metadata(&hook_path)?;
    let mut permissions = metadata.permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&hook_path, permissions)
        .context(format!("failed to set permissions on: {}", hook_path.display()))?;

    tracing::info!(
        "installed {} hook at {}",
        hook_type,
        hook_path.display()
    );

    Ok(())
}

/// Remove a git hook from a repository.
pub async fn remove_hook(repo_path: &Path, hook_type: HookType) -> Result<()> {
    let hook_path = repo_path.join(".git").join("hooks").join(hook_type.filename());

    if !hook_path.exists() {
        tracing::debug!("hook does not exist, nothing to remove: {}", hook_path.display());
        return Ok(());
    }

    fs::remove_file(&hook_path)
        .context(format!("failed to remove hook: {}", hook_path.display()))?;

    tracing::info!("removed {} hook from {}", hook_type, repo_path.display());

    Ok(())
}

/// List all installed git hooks in a repository.
pub async fn list_hooks(repo_path: &Path) -> Result<Vec<(HookType, PathBuf)>> {
    let hooks_dir = repo_path.join(".git").join("hooks");

    if !hooks_dir.exists() {
        return Ok(Vec::new());
    }

    let entries = fs::read_dir(&hooks_dir)
        .context(format!("failed to read hooks directory: {}", hooks_dir.display()))?;

    let mut installed = Vec::new();
    for entry in entries {
        let entry = entry?;
        let path = entry.path();

        if !path.is_file() {
            continue;
        }

        if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
            if let Ok(hook_type) = name.parse::<HookType>() {
                installed.push((hook_type, path));
            }
        }
    }

    installed.sort_by_key(|(hook_type, _)| *hook_type);
    Ok(installed)
}

// ---------------------------------------------------------------------------
// Scanning
// ---------------------------------------------------------------------------

/// Scan staged files for secrets.
///
/// This is used by the pre-commit hook to check files that are about to be committed.
pub async fn scan_staged_files(repo_path: &Path) -> Result<Vec<SecretFinding>> {
    validate_repo_path(repo_path).context("staged file scanning requires a git repository")?;

    let staged_files = get_staged_files(repo_path).await?;

    if staged_files.is_empty() {
        tracing::debug!("no staged files to scan");
        return Ok(Vec::new());
    }

    tracing::info!("scanning {} staged files for secrets", staged_files.len());

    let result = scan_files(repo_path, &staged_files, true).await?;

    if result.has_secrets() {
        print_findings(&result, "staged files");
    }

    Ok(result.findings)
}

/// Scan all files in a commit for secrets.
///
/// This is used by the pre-push hook to check the entire commit being pushed.
pub async fn scan_commit(repo_path: &Path, commit: &str) -> Result<Vec<SecretFinding>> {
    validate_repo_path(repo_path).context("commit scanning requires a git repository")?;

    let files = get_commit_files(repo_path, commit).await?;

    if files.is_empty() {
        tracing::debug!("no files in commit {} to scan", commit);
        return Ok(Vec::new());
    }

    tracing::info!(
        "scanning {} files in commit {} for secrets",
        files.len(),
        commit
    );

    let result = scan_files(repo_path, &files, false).await?;

    if result.has_secrets() {
        print_findings(&result, &format!("commit {}", commit));
    }

    Ok(result.findings)
}

/// Scan files that are about to be pushed.
///
/// Scans all commits in the push (everything not on the remote).
pub async fn scan_push(repo_path: &Path) -> Result<Vec<SecretFinding>> {
    validate_repo_path(repo_path).context("push scanning requires a git repository")?;

    let files = get_push_files(repo_path).await?;

    if files.is_empty() {
        tracing::debug!("no files in push to scan");
        return Ok(Vec::new());
    }

    tracing::info!("scanning {} files in push for secrets", files.len());

    let result = scan_files(repo_path, &files, false).await?;

    if result.has_secrets() {
        print_findings(&result, "push");
    }

    Ok(result.findings)
}

// ---------------------------------------------------------------------------
// Git Operations (Internal)
// ---------------------------------------------------------------------------

/// Get the list of staged files from git.
async fn get_staged_files(repo_path: &Path) -> Result<Vec<PathBuf>> {
    let output = AsyncCommand::new("git")
        .args(["-C"])
        .arg(repo_path)
        .args(["diff", "--cached", "--name-only", "-z"])
        .output()
        .await
        .context("failed to run git diff --cached")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("git diff --cached failed: {}", stderr.trim());
    }

    parse_null_separated_paths(&output.stdout)
}

/// Get the list of files in a commit.
async fn get_commit_files(repo_path: &Path, commit: &str) -> Result<Vec<PathBuf>> {
    // Get the parent commit to diff against
    let parent = if commit == "HEAD" || commit.is_empty() {
        "HEAD~1"
    } else {
        commit
    };

    let output = AsyncCommand::new("git")
        .args(["-C"])
        .arg(repo_path)
        .args(["diff", "--name-only", "-z", &format!("{}..{}", parent, commit)])
        .output()
        .await
        .context("failed to run git diff")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("git diff failed: {}", stderr.trim());
    }

    parse_null_separated_paths(&output.stdout)
}

/// Get the list of files that would be pushed.
async fn get_push_files(repo_path: &Path) -> Result<Vec<PathBuf>> {
    // Get commits being pushed
    let output = AsyncCommand::new("git")
        .args(["-C"])
        .arg(repo_path)
        .args(["log", "--format=%H", "origin/master..HEAD"])
        .output()
        .await
        .context("failed to run git log for push")?;

    if !output.status.success() {
        // Try master branch as fallback
        let output = AsyncCommand::new("git")
            .args(["-C"])
            .arg(repo_path)
            .args(["log", "--format=%H", "origin/main..HEAD"])
            .output()
            .await
            .context("failed to run git log for push")?;

        if !output.status.success() {
            // No upstream or no commits to push
            return Ok(Vec::new());
        }
    }

    let commits_output = String::from_utf8_lossy(&output.stdout);
    let commits: Vec<&str> = commits_output
        .lines()
        .filter(|l| !l.is_empty())
        .collect();

    if commits.is_empty() {
        return Ok(Vec::new());
    }

    // Get files in all commits
    let first = commits.first().unwrap();
    let last = commits.last().unwrap();

    let diff_output = AsyncCommand::new("git")
        .args(["-C"])
        .arg(repo_path)
        .args(["diff", "--name-only", "-z", &format!("{}~1..{}", first, first), "--", &format!("{}..{}", first, last)])
        .output()
        .await
        .context("failed to run git diff for push")?;

    if !diff_output.status.success() {
        return Ok(Vec::new());
    }

    parse_null_separated_paths(&diff_output.stdout)
}

/// Parse null-separated file paths from git output.
fn parse_null_separated_paths(output: &[u8]) -> Result<Vec<PathBuf>> {
    if output.is_empty() {
        return Ok(Vec::new());
    }

    let s = String::from_utf8_lossy(output);
    let paths: Vec<PathBuf> = s
        .split('\0')
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
        .collect();

    Ok(paths)
}

/// Validate that a path is a git repository.
fn validate_repo_path(repo_path: &Path) -> Result<()> {
    if !repo_path.exists() {
        bail!("path does not exist: {}", repo_path.display());
    }

    let git_dir = repo_path.join(".git");
    if !git_dir.exists() && !repo_path.is_dir() {
        bail!("not a git repository: {}", repo_path.display());
    }

    // Verify it's actually a git repo by running a git command
    let output = std::process::Command::new("git")
        .args(["-C"])
        .arg(repo_path)
        .args(["rev-parse", "--git-dir"])
        .output()?;

    if !output.status.success() {
        bail!("not a git repository: {}", repo_path.display());
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// File Scanning
// ---------------------------------------------------------------------------

/// Scan a list of files for secrets.
async fn scan_files(
    repo_path: &Path,
    files: &[PathBuf],
    _use_staged_content: bool,
) -> Result<ScanResult> {
    let redactor = Redactor::new();
    let mut all_findings = Vec::new();
    let mut skipped_files = Vec::new();
    let mut files_scanned = 0;

    for file_path in files {
        let full_path = repo_path.join(file_path);

        // Skip directories
        if full_path.is_dir() {
            continue;
        }

        // Skip binary files
        if is_binary_file(&full_path) {
            skipped_files.push(file_path.clone());
            continue;
        }

        match scan_file_content(&full_path, &redactor) {
            Ok(findings) => {
                files_scanned += 1;
                for mut finding in findings {
                    // Make path relative to repo root
                    finding.file = file_path.clone();
                    all_findings.push(finding);
                }
            }
            Err(e) => {
                tracing::warn!("failed to scan {}: {}", file_path.display(), e);
                skipped_files.push(file_path.clone());
            }
        }
    }

    Ok(ScanResult {
        findings: all_findings,
        files_scanned,
        skipped_files,
    })
}

/// Scan a single file for secrets.
fn scan_file_content(path: &Path, redactor: &Redactor) -> Result<Vec<SecretFinding>> {
    let content = fs::read_to_string(path)?;

    let mut findings = Vec::new();

    for (line_num, line) in content.lines().enumerate() {
        let redacted_line = redactor.redact(line);

        // If the line changed after redaction, there's a secret
        if redacted_line != line {
            let secret_type = detect_secret_type(line, redactor);
            let finding = SecretFinding::new(
                path.to_path_buf(),
                line_num + 1, // 1-indexed
                secret_type,
                line,
            );

            // Create finding with original line redacted
            findings.push(SecretFinding {
                line_content: redacted_line,
                ..finding
            });
        }
    }

    Ok(findings)
}

/// Check if a file is binary.
fn is_binary_file(path: &Path) -> bool {
    // First check by extension
    if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
        let binary_exts = [
            "png", "jpg", "jpeg", "gif", "bmp", "ico", "webp", "svg", "pdf",
            "zip", "gz", "bz2", "xz", "tar", "tgz",
            "exe", "dll", "so", "dylib",
            "woff", "woff2", "ttf", "otf", "eot",
            "mp3", "mp4", "wav", "avi", "mov",
            "db", "sqlite", "sqlite3",
            "class", "pyc", "o", "a",
        ];

        if binary_exts.contains(&ext.to_lowercase().as_str()) {
            return true;
        }
    }

    // Read first 8KB and look for null bytes
    if let Ok(mut file) = fs::File::open(path) {
        use std::io::Read;
        let mut buffer = [0u8; 8192];
        if let Ok(bytes_read) = file.read(&mut buffer) {
            return buffer[..bytes_read].contains(&0);
        }
    }

    false
}

/// Detect the type of secret from the matched line.
#[allow(dead_code)]
fn detect_secret_type(line: &str, _redactor: &Redactor) -> String {
    let lower = line.to_lowercase();

    // Order matters - more specific patterns first
    if lower.contains("-----begin") && lower.contains("private key") {
        "Private Key".to_string()
    } else if lower.contains("-----begin") {
        "Certificate/Key".to_string()
    } else if lower.contains("jwt") || lower.contains("eyj") {
        "JWT Token".to_string()
    } else if lower.contains("aws") || lower.contains("akia") {
        "AWS Access Key".to_string()
    } else if lower.contains("sk-") {
        "API Key".to_string()
    } else if lower.contains("api_key") || lower.contains("api-key") {
        "API Key".to_string()
    } else if lower.contains("_key=") || lower.contains("_token=")
        || lower.contains("_secret=")
    {
        "Environment Secret".to_string()
    } else if lower.contains("password") || lower.contains("passwd")
        || lower.contains("pwd:")
    {
        "Password".to_string()
    } else if lower.contains("token") || lower.contains("bearer") {
        "Token".to_string()
    } else if lower.contains("secret") {
        "Secret".to_string()
    } else {
        "Secret".to_string()
    }
}

/// Print findings in a human-readable format.
fn print_findings(result: &ScanResult, context: &str) {
    eprintln!();
    eprintln!("[guard] Secret scan results for {}:", context);
    eprintln!();

    // Group findings by file
    use std::collections::HashMap;
    let mut by_file: HashMap<PathBuf, Vec<&SecretFinding>> = HashMap::new();

    for finding in &result.findings {
        by_file.entry(finding.file.clone())
            .or_default()
            .push(finding);
    }

    for (file, findings) in &by_file {
        eprintln!("  {}", file.display());
        for finding in findings {
            eprintln!("    line {:>4}: [{}] {}", finding.line, finding.secret_type, finding.line_content);
        }
        eprintln!();
    }

    eprintln!("[guard] Found {} secret(s) in {} file(s)", result.secret_count(), by_file.len());
    eprintln!();
}

// ---------------------------------------------------------------------------
// Hook Script Rendering
// ---------------------------------------------------------------------------

/// Render the content of a hook script.
fn render_hook_script(hook_type: HookType) -> String {
    let guard_binary = find_guard_binary_for_hook();

    let scan_args = match hook_type {
        HookType::PreCommit => "--staged",
        HookType::PrePush => "--push",
    };

    let description = match hook_type {
        HookType::PreCommit => "pre-commit",
        HookType::PrePush => "pre-push",
    };

    format!(
        r#"#!/bin/sh
# git hook: {description}
# Generated by ssh-guard
# Do not edit manually - regenerate with: guard git-hook install

# Scan for secrets
{guard_binary} git-hook scan {scan_args}
result=$?

if [ $result -ne 0 ]; then
    echo ""
    echo "[guard] Commit blocked: secrets detected in {description} hook."
    echo "[guard] Review the findings above and remove secrets before committing."
    echo "[guard] If you're certain the secrets are safe, use --no-verify to skip this hook."
    exit 1
fi

exit 0
"#,
        guard_binary = guard_binary,
        scan_args = scan_args,
        description = description,
    )
}

/// Find the guard binary path for use in hook scripts.
fn find_guard_binary_for_hook() -> String {
    // Check SSH_GUARD_BIN environment variable first
    if let Ok(path) = env::var("SSH_GUARD_BIN") {
        // Use simple quoting - just wrap in single quotes
        return format!("'{}'", path.replace('\'', "'\\''"));
    }

    // Try to find guard in PATH
    if let Ok(path) = env::var("PATH") {
        for dir in path.split(':') {
            let candidate = PathBuf::from(dir).join("guard");
            if candidate.exists() {
                let path_str = candidate.to_string_lossy().to_string();
                return format!("'{}'", path_str.replace('\'', "'\\''"));
            }
        }
    }

    // Fall back to assuming guard is in PATH (simple case, no quoting needed for plain 'guard')
    "guard".to_string()
}

/// Escape a string for safe use in a shell script.
fn shell_escape(s: &str) -> String {
    // Replace ' with '\'' (end quote, escaped quote, start new quote)
    let escaped = s.replace('\'', "'\\''");
    format!("'{}'", escaped)
}

// ---------------------------------------------------------------------------
// CLI Entry Points
// ---------------------------------------------------------------------------

/// Install hooks from CLI.
pub async fn cli_install(repo_path: Option<PathBuf>, hook_type: HookType) -> Result<()> {
    let repo = repo_path.unwrap_or_else(|| std::env::current_dir().unwrap_or_default());

    install_hook(&repo, hook_type).await?;

    println!(
        "Installed {} hook at {}/.git/hooks/{}",
        hook_type,
        repo.display(),
        hook_type.filename()
    );
    println!("The hook will scan for secrets before {} operations.", hook_type);

    Ok(())
}

/// Scan from CLI.
pub async fn cli_scan(
    repo_path: Option<PathBuf>,
    staged: bool,
    commit: Option<String>,
    push: bool,
) -> Result<()> {
    let repo = repo_path.unwrap_or_else(|| std::env::current_dir().unwrap_or_default());

    let findings = if staged {
        scan_staged_files(&repo).await?
    } else if let Some(ref sha) = commit {
        scan_commit(&repo, sha).await?
    } else if push {
        scan_push(&repo).await?
    } else {
        bail!("must specify --staged, --commit, or --push");
    };

    if findings.is_empty() {
        println!("No secrets detected.");
        Ok(())
    } else {
        println!("Found {} secret(s).", findings.len());
        std::process::exit(1);
    }
}

/// List installed hooks from CLI.
pub async fn cli_list(repo_path: Option<PathBuf>) -> Result<()> {
    let repo = repo_path.unwrap_or_else(|| std::env::current_dir().unwrap_or_default());

    let hooks = list_hooks(&repo).await?;

    if hooks.is_empty() {
        println!("No hooks installed.");
    } else {
        println!("Installed hooks:");
        for (hook_type, path) in &hooks {
            println!("  {}: {}", hook_type, path.display());
        }
    }

    Ok(())
}

/// Remove hooks from CLI.
pub async fn cli_remove(repo_path: Option<PathBuf>, hook_type: HookType) -> Result<()> {
    let repo = repo_path.unwrap_or_else(|| std::env::current_dir().unwrap_or_default());

    remove_hook(&repo, hook_type).await?;

    println!(
        "Removed {} hook from {}",
        hook_type,
        repo.display()
    );

    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -------------------------------------------------------------------------
    // HookType parsing and conversion
    // -------------------------------------------------------------------------

    #[test]
    fn test_hook_type_parsing() {
        assert_eq!("pre-commit".parse::<HookType>().unwrap(), HookType::PreCommit);
        assert_eq!("pre-push".parse::<HookType>().unwrap(), HookType::PrePush);
        assert_eq!("precommit".parse::<HookType>().unwrap(), HookType::PreCommit);
        assert_eq!("prepush".parse::<HookType>().unwrap(), HookType::PrePush);
        assert_eq!("PRE-COMMIT".parse::<HookType>().unwrap(), HookType::PreCommit);
        assert!("invalid".parse::<HookType>().is_err());
    }

    #[test]
    fn test_hook_type_display() {
        assert_eq!(HookType::PreCommit.to_string(), "pre-commit");
        assert_eq!(HookType::PrePush.to_string(), "pre-push");
    }

    #[test]
    fn test_hook_type_filename() {
        assert_eq!(HookType::PreCommit.filename(), "pre-commit");
        assert_eq!(HookType::PrePush.filename(), "pre-push");
    }

    // -------------------------------------------------------------------------
    // Shell escaping
    // -------------------------------------------------------------------------

    #[test]
    fn test_shell_escape_simple() {
        assert_eq!(shell_escape("/usr/local/bin"), "'/usr/local/bin'");
    }

    #[test]
    fn test_shell_escape_with_single_quote() {
        assert_eq!(shell_escape("O'Brien"), "'O'\\''Brien'");
    }

    #[test]
    fn test_shell_escape_empty() {
        assert_eq!(shell_escape(""), "''");
    }

    #[test]
    fn test_shell_escape_with_spaces() {
        assert_eq!(shell_escape("/path with spaces"), "'/path with spaces'");
    }

    // -------------------------------------------------------------------------
    // Secret type detection
    // -------------------------------------------------------------------------

    #[test]
    fn test_detect_secret_type_aws() {
        let redactor = Redactor::new();
        assert_eq!(
            detect_secret_type("AWS_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE", &redactor),
            "AWS Access Key"
        );
        assert_eq!(
            detect_secret_type("aws_secret=abc123", &redactor),
            "AWS Access Key"
        );
    }

    #[test]
    fn test_detect_secret_type_api_key() {
        let redactor = Redactor::new();
        assert_eq!(
            detect_secret_type("api_key=sk-abcdefghijklmnop", &redactor),
            "API Key"
        );
        assert_eq!(
            detect_secret_type("API-KEY: sk_live_xxx", &redactor),
            "API Key"
        );
    }

    #[test]
    fn test_detect_secret_type_password() {
        let redactor = Redactor::new();
        assert_eq!(
            detect_secret_type("password=mypassword", &redactor),
            "Password"
        );
        assert_eq!(
            detect_secret_type("passwd: secret", &redactor),
            "Password"
        );
    }

    #[test]
    fn test_detect_secret_type_token() {
        let redactor = Redactor::new();
        // JWT tokens starting with "eyJ" are detected as JWT Token
        assert_eq!(
            detect_secret_type("token=eyJhbGciOiJIUzI1NiJ9", &redactor),
            "JWT Token"
        );
        assert_eq!(
            detect_secret_type("Authorization: Bearer xxx", &redactor),
            "Token"
        );
    }

    #[test]
    fn test_detect_secret_type_private_key() {
        let redactor = Redactor::new();
        assert_eq!(
            detect_secret_type("-----BEGIN RSA PRIVATE KEY-----", &redactor),
            "Private Key"
        );
    }

    #[test]
    fn test_detect_secret_type_certificate() {
        let redactor = Redactor::new();
        assert_eq!(
            detect_secret_type("-----BEGIN CERTIFICATE-----", &redactor),
            "Certificate/Key"
        );
    }

    #[test]
    fn test_detect_secret_type_env_secret() {
        let redactor = Redactor::new();
        // MY_API_KEY contains "api_key" so it detects as "API Key"
        assert_eq!(
            detect_secret_type("MY_API_KEY=secret123", &redactor),
            "API Key"
        );
        // GITHUB_TOKEN contains "_token=" so it detects as "Environment Secret"
        assert_eq!(
            detect_secret_type("GITHUB_TOKEN=ghp_xxx", &redactor),
            "Environment Secret"
        );
    }

    #[test]
    fn test_detect_secret_type_fallback() {
        let redactor = Redactor::new();
        assert_eq!(detect_secret_type("unknown_pattern=xyz", &redactor), "Secret");
    }

    // -------------------------------------------------------------------------
    // Binary file detection
    // -------------------------------------------------------------------------

    #[test]
    fn test_is_binary_by_extension() {
        let temp_dir = tempfile::tempdir().unwrap();
        let bin_path = temp_dir.path().join("image.png");

        // Create a non-binary file with .png extension
        fs::write(&bin_path, "not really a png").unwrap();

        // Should be treated as binary by extension
        assert!(is_binary_file(&bin_path));
    }

    #[test]
    fn test_is_binary_by_content() {
        let temp_dir = tempfile::tempdir().unwrap();
        let bin_path = temp_dir.path().join("file.bin");

        // Create a file with null bytes
        fs::write(&bin_path, b"hello\x00world").unwrap();

        assert!(is_binary_file(&bin_path));
    }

    #[test]
    fn test_is_not_binary_text_file() {
        let temp_dir = tempfile::tempdir().unwrap();
        let text_path = temp_dir.path().join("file.txt");

        fs::write(&text_path, "just some text content\nwith multiple lines").unwrap();

        assert!(!is_binary_file(&text_path));
    }

    // -------------------------------------------------------------------------
    // Null-separated path parsing
    // -------------------------------------------------------------------------

    #[test]
    fn test_parse_null_separated_paths() {
        let input = b"file1.txt\0file2.txt\0file3.txt\0";
        let paths = parse_null_separated_paths(input).unwrap();

        assert_eq!(paths.len(), 3);
        assert_eq!(paths[0], PathBuf::from("file1.txt"));
        assert_eq!(paths[1], PathBuf::from("file2.txt"));
        assert_eq!(paths[2], PathBuf::from("file3.txt"));
    }

    #[test]
    fn test_parse_null_separated_paths_empty() {
        let paths = parse_null_separated_paths(b"").unwrap();
        assert!(paths.is_empty());
    }

    #[test]
    fn test_parse_null_separated_paths_single() {
        let input = b"only_one.txt\0";
        let paths = parse_null_separated_paths(input).unwrap();

        assert_eq!(paths.len(), 1);
        assert_eq!(paths[0], PathBuf::from("only_one.txt"));
    }

    // -------------------------------------------------------------------------
    // Scan result
    // -------------------------------------------------------------------------

    #[test]
    fn test_scan_result_has_secrets() {
        let empty = ScanResult {
            findings: vec![],
            files_scanned: 0,
            skipped_files: vec![],
        };
        assert!(!empty.has_secrets());

        let with_findings = ScanResult {
            findings: vec![SecretFinding {
                file: PathBuf::from("test.txt"),
                line: 1,
                secret_type: "Password".to_string(),
                matched_text: "[REDACTED]".to_string(),
                line_content: "password=secret".to_string(),
            }],
            files_scanned: 1,
            skipped_files: vec![],
        };
        assert!(with_findings.has_secrets());
    }

    #[test]
    fn test_scan_result_secret_count() {
        let result = ScanResult {
            findings: vec![
                SecretFinding {
                    file: PathBuf::from("a.txt"),
                    line: 1,
                    secret_type: "Password".to_string(),
                    matched_text: "[REDACTED]".to_string(),
                    line_content: String::new(),
                },
                SecretFinding {
                    file: PathBuf::from("b.txt"),
                    line: 2,
                    secret_type: "API Key".to_string(),
                    matched_text: "[REDACTED]".to_string(),
                    line_content: String::new(),
                },
            ],
            files_scanned: 2,
            skipped_files: vec![],
        };

        assert_eq!(result.secret_count(), 2);
    }

    // -------------------------------------------------------------------------
    // File content scanning
    // -------------------------------------------------------------------------

    #[test]
    fn test_scan_file_content_finds_secrets() {
        let temp_dir = tempfile::tempdir().unwrap();
        let file_path = temp_dir.path().join("config.txt");

        fs::write(
            &file_path,
            "host=localhost\npassword=supersecret\nuser=admin\n",
        )
        .unwrap();

        let redactor = Redactor::new();
        let findings = scan_file_content(&file_path, &redactor).unwrap();

        assert!(!findings.is_empty());
        assert!(findings.iter().any(|f| f.secret_type == "Password"));
    }

    #[test]
    fn test_scan_file_content_no_secrets() {
        let temp_dir = tempfile::tempdir().unwrap();
        let file_path = temp_dir.path().join("clean.txt");

        fs::write(&file_path, "host=localhost\nuser=admin\nport=8080\n").unwrap();

        let redactor = Redactor::new();
        let findings = scan_file_content(&file_path, &redactor).unwrap();

        assert!(findings.is_empty());
    }

    #[test]
    fn test_scan_file_content_multiple_secrets() {
        let temp_dir = tempfile::tempdir().unwrap();
        let file_path = temp_dir.path().join("config.txt");

        fs::write(
            &file_path,
            "password=first\napi_key=sk_test_xxx\ntoken=eyJxxx\npassword=second\n",
        )
        .unwrap();

        let redactor = Redactor::new();
        let findings = scan_file_content(&file_path, &redactor).unwrap();

        // Should find all 4 secrets
        assert_eq!(findings.len(), 4);
    }

    #[test]
    fn test_scan_file_content_redacts_line_content() {
        let temp_dir = tempfile::tempdir().unwrap();
        let file_path = temp_dir.path().join("config.txt");

        fs::write(&file_path, "AWS_SECRET=AKIAIOSFODNN7EXAMPLE\n").unwrap();

        let redactor = Redactor::new();
        let findings = scan_file_content(&file_path, &redactor).unwrap();

        assert!(!findings.is_empty());
        let finding = &findings[0];

        // The line_content should be redacted
        assert!(!finding.line_content.contains("AKIAIOSFODNN7EXAMPLE"));
        assert!(finding.line_content.contains("[REDACTED]"));
    }

    // -------------------------------------------------------------------------
    // Hook script rendering
    // -------------------------------------------------------------------------

    #[test]
    fn test_render_pre_commit_hook_script() {
        let content = render_hook_script(HookType::PreCommit);

        assert!(content.contains("#!/bin/sh"));
        // The scan args are embedded in the script
        assert!(content.contains("--staged"));
        assert!(content.contains("pre-commit"));
        assert!(content.contains("secrets detected"));
    }

    #[test]
    fn test_render_pre_push_hook_script() {
        let content = render_hook_script(HookType::PrePush);

        assert!(content.contains("#!/bin/sh"));
        // The scan args are embedded in the script
        assert!(content.contains("--push"));
        assert!(content.contains("pre-push"));
    }

    #[test]
    fn test_hook_script_handles_secret_blocking() {
        let content = render_hook_script(HookType::PreCommit);

        // Should exit 1 when secrets are found
        assert!(content.contains("exit 1"));
        // Should exit 0 when no secrets
        assert!(content.contains("exit 0"));
    }

    // -------------------------------------------------------------------------
    // Integration-style tests (require actual git repo)
    // -------------------------------------------------------------------------

    #[tokio::test]
    async fn test_validate_repo_path_rejects_non_git() {
        let temp_dir = tempfile::tempdir().unwrap();

        let result = validate_repo_path(temp_dir.path());
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not a git repository"));
    }

    #[tokio::test]
    async fn test_validate_repo_path_rejects_nonexistent() {
        let result = validate_repo_path(Path::new("/nonexistent/path"));
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_validate_repo_path_accepts_git_repo() {
        // Create a temp directory with a git repo
        let temp_dir = tempfile::tempdir().unwrap();

        // Initialize git repo
        let output = std::process::Command::new("git")
            .args(["init", "--quiet"])
            .current_dir(temp_dir.path())
            .output()
            .unwrap();

        assert!(output.status.success());

        let result = validate_repo_path(temp_dir.path());
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_install_and_remove_hook() {
        // Create a temp directory with a git repo
        let temp_dir = tempfile::tempdir().unwrap();

        // Initialize git repo
        std::process::Command::new("git")
            .args(["init", "--quiet"])
            .current_dir(temp_dir.path())
            .output()
            .unwrap();

        // Install pre-commit hook
        install_hook(temp_dir.path(), HookType::PreCommit)
            .await
            .unwrap();

        let hook_path = temp_dir
            .path()
            .join(".git")
            .join("hooks")
            .join("pre-commit");
        assert!(hook_path.exists());

        // Verify hook is executable
        let metadata = fs::metadata(&hook_path).unwrap();
        let mode = metadata.permissions().mode() & 0o777;
        assert_eq!(mode, 0o755);

        // Remove the hook
        remove_hook(temp_dir.path(), HookType::PreCommit)
            .await
            .unwrap();
        assert!(!hook_path.exists());
    }

    #[tokio::test]
    async fn test_install_both_hooks() {
        let temp_dir = tempfile::tempdir().unwrap();

        // Initialize git repo
        std::process::Command::new("git")
            .args(["init", "--quiet"])
            .current_dir(temp_dir.path())
            .output()
            .unwrap();

        // Install both hooks
        install_hook(temp_dir.path(), HookType::PreCommit)
            .await
            .unwrap();
        install_hook(temp_dir.path(), HookType::PrePush).await.unwrap();

        let pre_commit = temp_dir
            .path()
            .join(".git")
            .join("hooks")
            .join("pre-commit");
        let pre_push = temp_dir
            .path()
            .join(".git")
            .join("hooks")
            .join("pre-push");

        assert!(pre_commit.exists());
        assert!(pre_push.exists());
    }

    #[tokio::test]
    async fn test_list_hooks() {
        let temp_dir = tempfile::tempdir().unwrap();

        // Initialize git repo
        std::process::Command::new("git")
            .args(["init", "--quiet"])
            .current_dir(temp_dir.path())
            .output()
            .unwrap();

        // Initially no hooks
        let hooks = list_hooks(temp_dir.path()).await.unwrap();
        assert!(hooks.is_empty());

        // Install a hook
        install_hook(temp_dir.path(), HookType::PreCommit)
            .await
            .unwrap();

        let hooks = list_hooks(temp_dir.path()).await.unwrap();
        assert_eq!(hooks.len(), 1);
        assert_eq!(hooks[0].0, HookType::PreCommit);
    }

    #[tokio::test]
    async fn test_list_hooks_nonexistent_repo() {
        // Test with non-existent directory
        let temp_dir = tempfile::tempdir().unwrap();
        let nonexistent = temp_dir.path().join("nonexistent");

        let hooks = list_hooks(&nonexistent).await.unwrap();
        assert!(hooks.is_empty());
    }

    #[tokio::test]
    async fn test_remove_nonexistent_hook() {
        let temp_dir = tempfile::tempdir().unwrap();

        // Initialize git repo
        std::process::Command::new("git")
            .args(["init", "--quiet"])
            .current_dir(temp_dir.path())
            .output()
            .unwrap();

        // Removing non-existent hook should not error
        remove_hook(temp_dir.path(), HookType::PreCommit)
            .await
            .unwrap();
    }

    // -------------------------------------------------------------------------
    // End-to-end secret scanning tests
    // -------------------------------------------------------------------------

    #[tokio::test]
    async fn test_scan_staged_files_no_secrets() {
        let temp_dir = tempfile::tempdir().unwrap();

        // Initialize git repo
        std::process::Command::new("git")
            .args(["init", "--quiet"])
            .current_dir(temp_dir.path())
            .output()
            .unwrap();

        // Create a clean file and stage it
        let file_path = temp_dir.path().join("clean.txt");
        fs::write(&file_path, "just some text\n").unwrap();

        std::process::Command::new("git")
            .args(["-C"])
            .arg(temp_dir.path())
            .args(["add", "."])
            .output()
            .unwrap();

        let findings = scan_staged_files(temp_dir.path()).await.unwrap();
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn test_scan_staged_files_with_secrets() {
        let temp_dir = tempfile::tempdir().unwrap();

        // Initialize git repo
        std::process::Command::new("git")
            .args(["init", "--quiet"])
            .current_dir(temp_dir.path())
            .output()
            .unwrap();

        // Create a file with a secret
        let file_path = temp_dir.path().join("config.txt");
        fs::write(&file_path, "password=supersecret123\n").unwrap();

        std::process::Command::new("git")
            .args(["-C"])
            .arg(temp_dir.path())
            .args(["add", "."])
            .output()
            .unwrap();

        let findings = scan_staged_files(temp_dir.path()).await.unwrap();
        assert!(!findings.is_empty());
    }

    #[tokio::test]
    async fn test_scan_staged_files_no_git_repo() {
        let temp_dir = tempfile::tempdir().unwrap();

        let result = scan_staged_files(temp_dir.path()).await;
        assert!(result.is_err());
    }
}
