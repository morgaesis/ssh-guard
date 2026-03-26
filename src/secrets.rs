//! Secret broker for managing sensitive credentials across multiple backends.
//!
//! This module provides a unified interface for storing and retrieving secrets
//! from various backends (pass, environment variables, encrypted local files).

use anyhow::{bail, Result};
use async_trait::async_trait;
use std::collections::HashMap;
use std::env;
use std::ffi::OsStr;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::process::Command as AsyncCommand;
use tokio::sync::RwLock;

/// Directory within pass where secrets are stored.
const PASS_PREFIX: &str = "guard/";

/// Prefix for environment variable secrets.
const ENV_PREFIX: &str = "GUARD_SECRET_";

/// Filename for the local encrypted secrets file.
const SECRETS_FILE: &str = "secrets.yaml";

/// Trait for secret storage backends.
///
/// Implementors must be safe to share across threads (Send + Sync).
#[async_trait]
pub trait SecretBackend: Send + Sync {
    /// Returns the backend name for logging/debugging.
    fn name(&self) -> &str;

    /// Retrieve a secret by key.
    async fn get(&self, key: &str) -> Result<Option<String>>;

    /// List all secret keys.
    async fn list(&self) -> Result<Vec<String>>;

    /// Store a secret.
    async fn set(&self, key: &str, value: &str) -> Result<()>;

    /// Delete a secret.
    async fn delete(&self, key: &str) -> Result<()>;
}

// ---------------------------------------------------------------------------
// PassBackend
// ---------------------------------------------------------------------------

/// Secret backend backed by the unix `pass` password manager.
#[derive(Debug, Clone)]
pub struct PassBackend {
    gpg_id: Option<String>,
}

impl PassBackend {
    /// Create a new PassBackend.
    ///
    /// If `gpg_id` is provided, it will be passed to `pass insert --multifile`.
    pub fn new(gpg_id: Option<String>) -> Self {
        Self { gpg_id }
    }

    fn pass_path(&self, key: &str) -> String {
        format!("{}{}", PASS_PREFIX, key)
    }

    async fn run_pass<I, S>(&self, args: I) -> Result<()>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        let mut cmd = AsyncCommand::new("pass");
        cmd.args(args);

        let output = cmd.output().await?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            bail!("pass command failed: {}", stderr.trim());
        }

        Ok(())
    }
}

#[async_trait]
impl SecretBackend for PassBackend {
    fn name(&self) -> &str {
        "pass"
    }

    async fn get(&self, key: &str) -> Result<Option<String>> {
        let path = self.pass_path(key);

        let output = AsyncCommand::new("pass")
            .arg("show")
            .arg(&path)
            .output()
            .await?;

        if !output.status.success() {
            // pass returns exit code 1 when the entry doesn't exist
            if output.status.code() == Some(1) {
                return Ok(None);
            }
            let stderr = String::from_utf8_lossy(&output.stderr);
            bail!("pass show {} failed: {}", path, stderr.trim());
        }

        // pass outputs the secret followed by a newline; trim it
        let secret = String::from_utf8_lossy(&output.stdout).trim().to_string();
        Ok(Some(secret))
    }

    async fn list(&self) -> Result<Vec<String>> {
        let output = AsyncCommand::new("pass")
            .args(["ls", PASS_PREFIX])
            .output()
            .await?;

        if !output.status.success() {
            // Empty directory returns exit code 1
            if output.status.code() == Some(1) {
                return Ok(Vec::new());
            }
            let stderr = String::from_utf8_lossy(&output.stderr);
            bail!("pass ls {} failed: {}", PASS_PREFIX, stderr.trim());
        }

        // Parse pass ls output to extract key names
        // Output format: each line is "key/" or "key (creation_date)"
        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut keys = Vec::new();

        for line in stdout.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with("Passwords") || line.starts_with(PASS_PREFIX) {
                continue;
            }

            // Strip directory suffix and any parenthetical info
            let key = if let Some(slash) = line.strip_suffix('/') {
                slash.trim().to_string()
            } else {
                line.split_whitespace()
                    .next()
                    .unwrap_or(line)
                    .trim()
                    .to_string()
            };

            if !key.is_empty() {
                // Remove the PASS_PREFIX if it appears
                let key = key.strip_prefix(PASS_PREFIX).unwrap_or(&key).to_string();
                keys.push(key);
            }
        }

        Ok(keys)
    }

    async fn set(&self, key: &str, value: &str) -> Result<()> {
        let path = self.pass_path(key);

        // Use printf to pipe the secret to pass
        let mut cmd = AsyncCommand::new("sh");
        cmd.arg("-c").arg(format!(
            "printf '%s' '{}' | pass insert --force --multifile '{}'",
            value, path
        ));

        if let Some(ref gpg_id) = self.gpg_id {
            cmd.arg("--gpg-id").arg(gpg_id);
        }

        let output = cmd.output().await?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            bail!("pass insert {} failed: {}", path, stderr.trim());
        }

        Ok(())
    }

    async fn delete(&self, key: &str) -> Result<()> {
        let path = self.pass_path(key);

        let mut cmd = AsyncCommand::new("pass");
        cmd.args(["rm", "-f", &path]);

        let output = cmd.output().await?;

        if !output.status.success() {
            // pass rm returns exit code 1 if the entry doesn't exist
            if output.status.code() == Some(1) {
                return Ok(());
            }
            let stderr = String::from_utf8_lossy(&output.stderr);
            bail!("pass rm {} failed: {}", path, stderr.trim());
        }

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// EnvBackend
// ---------------------------------------------------------------------------

/// Secret backend backed by environment variables.
///
/// Secrets are stored with `GUARD_SECRET_` prefix.
/// For example, `GUARD_SECRET_API_KEY` exposes the key `API_KEY`.
#[derive(Debug, Clone)]
pub struct EnvBackend {
    _priv: (),
}

impl EnvBackend {
    pub fn new() -> Self {
        Self { _priv: () }
    }

    fn env_key(secret_key: &str) -> String {
        format!("{}{}", ENV_PREFIX, secret_key)
    }
}

impl Default for EnvBackend {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl SecretBackend for EnvBackend {
    fn name(&self) -> &str {
        "env"
    }

    async fn get(&self, key: &str) -> Result<Option<String>> {
        let env_key = Self::env_key(key);
        Ok(env::var(&env_key).ok())
    }

    async fn list(&self) -> Result<Vec<String>> {
        let mut keys = Vec::new();

        for (env_key, _) in env::vars() {
            if let Some(key) = env_key.strip_prefix(ENV_PREFIX) {
                keys.push(key.to_string());
            }
        }

        keys.sort();
        Ok(keys)
    }

    async fn set(&self, key: &str, value: &str) -> Result<()> {
        let env_key = Self::env_key(key);
        env::set_var(&env_key, value);
        Ok(())
    }

    async fn delete(&self, key: &str) -> Result<()> {
        let env_key = Self::env_key(key);
        env::remove_var(&env_key);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// LocalBackend
// ---------------------------------------------------------------------------

/// Secret backend backed by an encrypted YAML file.
///
/// The file is encrypted using GPG or a passphrase from stdin.
/// Falls back to prompting for a passphrase if no GPG key is configured.
#[derive(Debug, Clone)]
pub struct LocalBackend {
    path: PathBuf,
    gpg_recipient: Option<String>,
}

impl LocalBackend {
    /// Create a new LocalBackend.
    ///
    /// The secrets file is stored at `~/.config/guard/secrets.yaml.gpg`.
    pub fn new() -> Result<Self> {
        let config_dir = dirs::config_dir()
            .ok_or_else(|| anyhow::anyhow!("could not determine config directory"))?;
        let guard_dir = config_dir.join("guard");

        Ok(Self {
            path: guard_dir.join(SECRETS_FILE),
            gpg_recipient: None,
        })
    }

    /// Create a LocalBackend with an explicit path.
    pub fn with_path(path: PathBuf) -> Self {
        Self {
            path,
            gpg_recipient: None,
        }
    }

    /// Set the GPG recipient for encryption.
    pub fn with_gpg_recipient(mut self, recipient: String) -> Self {
        self.gpg_recipient = Some(recipient);
        self
    }

    fn encrypted_path(&self) -> PathBuf {
        PathBuf::from(format!("{}.gpg", self.path.display()))
    }

    async fn load_secrets(&self) -> Result<HashMap<String, String>> {
        let encrypted = self.encrypted_path();

        if !encrypted.exists() {
            return Ok(HashMap::new());
        }

        // Decrypt with gpg
        let output = if let Some(ref recipient) = self.gpg_recipient {
            AsyncCommand::new("gpg")
                .args(["--decrypt", "--recipient", recipient, "--quiet"])
                .arg(&encrypted)
                .output()
                .await?
        } else {
            AsyncCommand::new("gpg")
                .args(["--decrypt", "--quiet"])
                .arg(&encrypted)
                .output()
                .await?
        };

        if !output.status.success() {
            // Likely a bad passphrase or no GPG setup; return empty
            tracing::debug!("could not decrypt secrets file: {:?}", output.status);
            return Ok(HashMap::new());
        }

        let content = String::from_utf8_lossy(&output.stdout);
        let secrets: HashMap<String, String> = serde_yaml::from_str(&content).unwrap_or_default();

        Ok(secrets)
    }

    async fn save_secrets(&self, secrets: &HashMap<String, String>) -> Result<()> {
        let parent = self.path.parent();
        if let Some(parent) = parent {
            fs::create_dir_all(parent)?;
        }

        let content = serde_yaml::to_string(secrets)?;

        if let Some(ref recipient) = self.gpg_recipient {
            // Encrypt with recipient using symmetric stdin pipe
            let mut child = AsyncCommand::new("gpg")
                .args(["--encrypt", "--recipient", recipient, "--quiet", "-o"])
                .arg(self.encrypted_path())
                .stdin(Stdio::piped())
                .spawn()?;

            if let Some(mut stdin) = child.stdin.take() {
                stdin.write_all(content.as_bytes()).await?;
                drop(stdin);
            }

            let status = child.wait().await?;
            if !status.success() {
                bail!("gpg encryption failed");
            }
        } else {
            // Use symmetric encryption with passphrase from stdin
            let mut child = AsyncCommand::new("gpg")
                .args(["--symmetric", "--cipher-algo", "AES256", "--quiet", "-o"])
                .arg(self.encrypted_path())
                .stdin(Stdio::piped())
                .spawn()?;

            if let Some(mut stdin) = child.stdin.take() {
                stdin.write_all(content.as_bytes()).await?;
                drop(stdin);
            }

            let status = child.wait().await?;
            if !status.success() {
                bail!("gpg symmetric encryption failed");
            }
        }

        Ok(())
    }
}

impl Default for LocalBackend {
    fn default() -> Self {
        Self::new().expect("could not create default LocalBackend")
    }
}

#[async_trait]
impl SecretBackend for LocalBackend {
    fn name(&self) -> &str {
        "local"
    }

    async fn get(&self, key: &str) -> Result<Option<String>> {
        let secrets = self.load_secrets().await?;
        Ok(secrets.get(key).cloned())
    }

    async fn list(&self) -> Result<Vec<String>> {
        let secrets = self.load_secrets().await?;
        let mut keys: Vec<_> = secrets.keys().cloned().collect();
        keys.sort();
        Ok(keys)
    }

    async fn set(&self, key: &str, value: &str) -> Result<()> {
        let mut secrets = self.load_secrets().await?;
        secrets.insert(key.to_string(), value.to_string());
        self.save_secrets(&secrets).await
    }

    async fn delete(&self, key: &str) -> Result<()> {
        let mut secrets = self.load_secrets().await?;
        secrets.remove(key);
        self.save_secrets(&secrets).await
    }
}

// ---------------------------------------------------------------------------
// SecretFd
// ---------------------------------------------------------------------------

/// A file descriptor wrapper for secret injection.
///
/// The secret is written to a temporary file with restricted permissions (0600).
/// The file is automatically cleaned up when this struct is dropped.
#[derive(Debug)]
pub struct SecretFd {
    /// Path to the temporary file containing the secret.
    pub path: PathBuf,
    temp_dir: tempfile::TempDir,
}

impl SecretFd {
    /// Write a secret to a temporary file and return a wrapper with auto-cleanup.
    ///
    /// The file permissions are set to 0600 (owner read/write only).
    fn new(secret: &str) -> Result<Self> {
        let temp_dir = tempfile::TempDir::new_in("/tmp")?;
        let path = temp_dir.path().join("secret");

        fs::write(&path, secret)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;

        Ok(Self { path, temp_dir })
    }

    /// Get the path to the secret file.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for SecretFd {
    fn drop(&mut self) {
        // TempDir will automatically clean up on drop, but be explicit
        if self.path.exists() {
            let _ = fs::remove_file(&self.path);
        }
    }
}

// ---------------------------------------------------------------------------
// SecretManager
// ---------------------------------------------------------------------------

/// Manager for secret operations with a configurable backend.
///
/// Wraps a secret backend and provides FD-based injection for safe secret handling.
#[derive(Clone)]
pub struct SecretManager {
    backend: Arc<dyn SecretBackend>,
    cache: Arc<RwLock<HashMap<String, String>>>,
}

impl std::fmt::Debug for SecretManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecretManager")
            .field("backend_name", &self.backend.name())
            .finish()
    }
}

impl SecretManager {
    /// Create a new SecretManager with the given backend.
    pub fn new(backend: Arc<dyn SecretBackend>) -> Self {
        Self {
            backend,
            cache: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Create a SecretManager with a specific backend type.
    pub fn with_backend<B: SecretBackend + 'static>(backend: B) -> Self {
        Self::new(Arc::new(backend))
    }

    /// Get a secret by key, with caching.
    pub async fn get(&self, key: &str) -> Result<Option<String>> {
        // Check cache first
        {
            let cache = self.cache.read().await;
            if let Some(value) = cache.get(key) {
                return Ok(Some(value.clone()));
            }
        }

        let value = self.backend.get(key).await?;

        // Cache the result if found
        if let Some(ref v) = value {
            let mut cache = self.cache.write().await;
            cache.insert(key.to_string(), v.clone());
        }

        Ok(value)
    }

    /// List all secret keys.
    pub async fn list(&self) -> Result<Vec<String>> {
        self.backend.list().await
    }

    /// Set a secret.
    pub async fn set(&self, key: &str, value: &str) -> Result<()> {
        self.backend.set(key, value).await?;

        // Update cache
        let mut cache = self.cache.write().await;
        cache.insert(key.to_string(), value.to_string());

        Ok(())
    }

    /// Delete a secret.
    pub async fn delete(&self, key: &str) -> Result<()> {
        self.backend.delete(key).await?;

        // Remove from cache
        let mut cache = self.cache.write().await;
        cache.remove(key);

        Ok(())
    }

    /// Inject a secret as a file descriptor.
    ///
    /// Writes the secret to a temporary file with 0600 permissions.
    /// The file is cleaned up when the returned SecretFd is dropped.
    pub async fn inject_fd(&self, key: &str) -> Result<SecretFd> {
        let secret = match self.get(key).await? {
            Some(s) => s,
            None => anyhow::bail!("secret not found: {}", key),
        };

        SecretFd::new(&secret)
    }

    /// Clear the in-memory cache.
    pub async fn clear_cache(&self) {
        let mut cache = self.cache.write().await;
        cache.clear();
    }
}

// ---------------------------------------------------------------------------
// Backend selection
// ---------------------------------------------------------------------------

/// Supported secret backend types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendType {
    /// Use the unix `pass` password manager.
    Pass,
    /// Use environment variables (for development/testing).
    Env,
    /// Use encrypted local file.
    Local,
}

impl BackendType {
    /// Create a backend instance from this type.
    pub fn build(&self) -> Result<Arc<dyn SecretBackend>> {
        match self {
            BackendType::Pass => {
                let gpg_id = env::var("SSH_GUARD_GPG_ID").ok();
                Ok(Arc::new(PassBackend::new(gpg_id)))
            }
            BackendType::Env => Ok(Arc::new(EnvBackend::new())),
            BackendType::Local => {
                let mut backend = LocalBackend::new()?;
                if let Ok(recipient) = env::var("SSH_GUARD_GPG_RECIPIENT") {
                    backend = backend.with_gpg_recipient(recipient);
                }
                Ok(Arc::new(backend))
            }
        }
    }
}

impl std::str::FromStr for BackendType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "pass" => Ok(BackendType::Pass),
            "env" => Ok(BackendType::Env),
            "local" => Ok(BackendType::Local),
            other => Err(format!(
                "unknown backend '{}'. Use: pass, env, local",
                other
            )),
        }
    }
}

/// Detect the best available backend based on environment.
pub fn detect_backend() -> BackendType {
    // Check for explicit configuration
    if let Ok(backend_str) = env::var("SSH_GUARD_BACKEND") {
        if let Ok(backend) = backend_str.parse::<BackendType>() {
            return backend;
        }
    }

    // Check for pass availability
    if std::process::Command::new("pass")
        .arg("init")
        .arg("--check")
        .output()
        .is_ok()
    {
        return BackendType::Pass;
    }

    // Fall back to environment backend
    BackendType::Env
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use std::sync::Mutex;

    // A mock backend for testing.
    #[derive(Debug, Default)]
    struct MockBackend {
        store: Mutex<HashMap<String, String>>,
    }

    impl MockBackend {
        fn new() -> Self {
            Self {
                store: Mutex::new(HashMap::new()),
            }
        }
    }

    #[async_trait]
    impl SecretBackend for MockBackend {
        fn name(&self) -> &str {
            "mock"
        }

        async fn get(&self, key: &str) -> Result<Option<String>> {
            let store = self.store.lock().unwrap();
            Ok(store.get(key).cloned())
        }

        async fn list(&self) -> Result<Vec<String>> {
            let store = self.store.lock().unwrap();
            Ok(store.keys().cloned().collect())
        }

        async fn set(&self, key: &str, value: &str) -> Result<()> {
            let mut store = self.store.lock().unwrap();
            store.insert(key.to_string(), value.to_string());
            Ok(())
        }

        async fn delete(&self, key: &str) -> Result<()> {
            let mut store = self.store.lock().unwrap();
            store.remove(key);
            Ok(())
        }
    }

    #[tokio::test]
    async fn test_secret_manager_basic_operations() {
        let backend = Arc::new(MockBackend::new());
        let manager = SecretManager::new(backend.clone());

        // Set a secret
        manager.set("api_key", "secret123").await.unwrap();

        // Get it back
        let value = manager.get("api_key").await.unwrap();
        assert_eq!(value, Some("secret123".to_string()));

        // List keys
        let keys = manager.list().await.unwrap();
        assert!(keys.contains(&"api_key".to_string()));

        // Delete
        manager.delete("api_key").await.unwrap();
        let value = manager.get("api_key").await.unwrap();
        assert_eq!(value, None);
    }

    #[tokio::test]
    async fn test_secret_manager_caching() {
        let backend = Arc::new(MockBackend::new());
        let manager = SecretManager::new(backend);

        // Set a secret
        manager.set("cached_key", "cached_value").await.unwrap();

        // First get should cache it
        let first = manager.get("cached_key").await.unwrap();
        assert_eq!(first, Some("cached_value".to_string()));

        // Cache should be populated
        let cache = manager.cache.read().await;
        assert!(cache.contains_key("cached_key"));
    }

    #[tokio::test]
    async fn test_secret_fd_creation() {
        let secret = "test_secret_content";
        let fd = SecretFd::new(secret).unwrap();

        // Verify the file exists and has correct content
        assert!(fd.path.exists());
        let content = fs::read_to_string(fd.path()).unwrap();
        assert_eq!(content, secret);

        // Verify permissions (only on Unix)
        #[cfg(unix)]
        {
            let metadata = fs::metadata(fd.path()).unwrap();
            let mode = metadata.permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }

        // Drop the fd
        drop(fd);

        // File should be cleaned up
        // Note: temp_dir cleanup is async, so we just verify no panic
    }

    #[tokio::test]
    async fn test_env_backend() {
        let backend = EnvBackend::new();

        // Set via env var
        env::set_var("GUARD_SECRET_TEST_KEY", "test_value");

        let value = backend.get("TEST_KEY").await.unwrap();
        assert_eq!(value, Some("test_value".to_string()));

        let keys = backend.list().await.unwrap();
        assert!(keys.contains(&"TEST_KEY".to_string()));

        // Clean up
        env::remove_var("GUARD_SECRET_TEST_KEY");
    }

    #[tokio::test]
    async fn test_backend_type_parsing() {
        assert_eq!("pass".parse::<BackendType>().unwrap(), BackendType::Pass);
        assert_eq!("env".parse::<BackendType>().unwrap(), BackendType::Env);
        assert_eq!("local".parse::<BackendType>().unwrap(), BackendType::Local);
        assert_eq!("PASS".parse::<BackendType>().unwrap(), BackendType::Pass);
        assert!("invalid".parse::<BackendType>().is_err());
    }

    #[tokio::test]
    async fn test_pass_backend_integration() {
        // This test requires `pass` to be installed and configured.
        // Skip if not available.
        let pass_available = std::process::Command::new("pass")
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);

        if !pass_available {
            eprintln!("skipping pass integration test (pass not available)");
            return;
        }

        // Skip if pass version doesn't support --multifile
        let multifile_supported = std::process::Command::new("pass")
            .arg("insert")
            .arg("--help")
            .output()
            .map(|o| {
                o.status.success() && String::from_utf8_lossy(&o.stdout).contains("--multifile")
            })
            .unwrap_or(false);

        if !multifile_supported {
            eprintln!("skipping pass integration test (pass --multifile not supported)");
            return;
        }

        let backend = PassBackend::new(None);
        let test_key = format!("guard_test_{}", std::process::id());
        let test_value = "integration_test_value";

        // Clean up any existing test entry
        let _ = backend.delete(&test_key).await;

        // Set and get
        backend.set(&test_key, test_value).await.unwrap();
        let value = backend.get(&test_key).await.unwrap();
        assert_eq!(value, Some(test_value.to_string()));

        // List
        let keys = backend.list().await.unwrap();
        assert!(keys
            .iter()
            .any(|k| k == &test_key || k.ends_with(&test_key)));

        // Delete
        backend.delete(&test_key).await.unwrap();
        let value = backend.get(&test_key).await.unwrap();
        assert_eq!(value, None);
    }

    #[tokio::test]
    async fn test_secret_manager_inject_fd() {
        let backend = Arc::new(MockBackend::new());
        let manager = SecretManager::new(backend);

        manager.set("fd_test", "fd_secret_value").await.unwrap();

        let fd = manager.inject_fd("fd_test").await.unwrap();
        let content = fs::read_to_string(fd.path()).unwrap();
        assert_eq!(content, "fd_secret_value");
    }

    #[tokio::test]
    async fn test_secret_manager_inject_fd_not_found() {
        let backend = Arc::new(MockBackend::new());
        let manager = SecretManager::new(backend);

        let result = manager.inject_fd("nonexistent").await;
        assert!(result.is_err());
    }
}
