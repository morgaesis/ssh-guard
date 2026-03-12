use regex::Regex;
use std::sync::OnceLock;

/// Compiled redaction patterns, initialized once.
fn redaction_patterns() -> &'static Vec<(Regex, &'static str)> {
    static PATTERNS: OnceLock<Vec<(Regex, &str)>> = OnceLock::new();
    PATTERNS.get_or_init(|| {
        vec![
            // 1. Named secret vars: *_TOKEN, *_KEY, *_SECRET, *_PASSWORD, *_CREDENTIAL, *_AUTH
            (
                Regex::new(r#"(?i)([_-](TOKEN|KEY|SECRET|PASSWORD|PASSWD|CREDENTIAL|AUTH)\s*[=:]\s*["']?)([^"'\s}{,]+)"#).unwrap(),
                "${1}[REDACTED]",
            ),
            // 2. Bare keywords: password, passwd, secret, token, bearer
            (
                Regex::new(r#"(?i)((password|passwd|secret|token|bearer)\s*[=:]\s*["']?)([^"'\s}{,]+)"#).unwrap(),
                "${1}[REDACTED]",
            ),
            // 3. PEM private key blocks
            (
                Regex::new(r"(-----BEGIN [A-Z ]*PRIVATE KEY-----).*").unwrap(),
                "$1 [REDACTED]",
            ),
            // 4. sk-* prefixed keys (OpenAI, Anthropic, Stripe, etc.)
            (
                Regex::new(r"sk-[A-Za-z0-9_-]{20,}").unwrap(),
                "[REDACTED]",
            ),
            // 5. JWT tokens (eyJ header)
            (
                Regex::new(r"eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+").unwrap(),
                "[REDACTED]",
            ),
            // 6. Catch-all: ANY_VAR=<high-entropy value> (hex 20+, base64 24+, or mixed-alnum 30+)
            //    This catches things like X_CT0=9c52ab..., SESSION_ID=a3f8b1..., etc.
            (
                Regex::new(r#"(?i)([A-Z_][A-Z0-9_]*\s*[=:]\s*["']?)([0-9a-f]{20,}|[A-Za-z0-9+/]{24,}={0,2}|[A-Za-z0-9_-]{40,})(["']?\s)"#).unwrap(),
                "${1}[REDACTED]${3}",
            ),
            // 7. Standalone long base64 blobs (lines of 40+ base64 chars, like encoded keys/certs)
            (
                Regex::new(r"^[A-Za-z0-9+/]{40,}={0,2}$").unwrap(),
                "[REDACTED]",
            ),
        ]
    })
}

/// Apply redaction patterns to the given text, replacing sensitive values with [REDACTED].
pub fn redact_output(text: &str) -> String {
    let patterns = redaction_patterns();
    let mut result = text.to_string();

    for (pattern, replacement) in patterns {
        result = pattern.replace_all(&result, *replacement).to_string();
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_redact_token_env_var() {
        let input = "MY_TOKEN=abc123secret";
        let output = redact_output(input);
        assert!(output.contains("[REDACTED]"), "got: {output}");
        assert!(!output.contains("abc123secret"), "got: {output}");
    }

    #[test]
    fn test_redact_password() {
        let input = "password=mysecretpassword";
        let output = redact_output(input);
        assert!(output.contains("[REDACTED]"), "got: {output}");
        assert!(!output.contains("mysecretpassword"), "got: {output}");
    }

    #[test]
    fn test_redact_bearer_token() {
        let input = "bearer: some_long_bearer_token_value";
        let output = redact_output(input);
        assert!(output.contains("[REDACTED]"), "got: {output}");
        assert!(
            !output.contains("some_long_bearer_token_value"),
            "got: {output}"
        );
    }

    #[test]
    fn test_redact_private_key() {
        let input = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpA...content...";
        let output = redact_output(input);
        assert!(output.contains("[REDACTED]"), "got: {output}");
    }

    #[test]
    fn test_redact_sk_key() {
        let input = "api_key: sk-abcdefghijklmnopqrstuvwxyz";
        let output = redact_output(input);
        assert!(output.contains("[REDACTED]"), "got: {output}");
        assert!(
            !output.contains("sk-abcdefghijklmnopqrstuvwxyz"),
            "got: {output}"
        );
    }

    #[test]
    fn test_redact_jwt() {
        let input = "token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        let output = redact_output(input);
        assert!(output.contains("[REDACTED]"), "got: {output}");
        assert!(!output.contains("eyJhbGci"), "got: {output}");
    }

    #[test]
    fn test_no_redaction_needed() {
        let input = "total 48\ndrwxr-xr-x  5 user user 4096 Jan  1 00:00 .\n";
        let output = redact_output(input);
        assert_eq!(output, input);
    }

    #[test]
    fn test_redact_api_secret() {
        let input = "API_SECRET=verysecretvalue123";
        let output = redact_output(input);
        assert!(output.contains("[REDACTED]"), "got: {output}");
        assert!(!output.contains("verysecretvalue123"), "got: {output}");
    }

    // --- New tests for the gaps ---

    #[test]
    fn test_redact_hex_cookie_value() {
        // X_CT0=9c52ab235e556a3f... -- no KEY/TOKEN in name, but long hex value
        let input = "X_CT0=9c52ab235e556a3f8b1d2e4f6a7c9d0e1f2a3b4c5d6e7f \n";
        let output = redact_output(input);
        assert!(output.contains("[REDACTED]"), "got: {output}");
        assert!(
            !output.contains("9c52ab235e556a3f"),
            "hex value should be redacted, got: {output}"
        );
    }

    #[test]
    fn test_redact_base64_env_value() {
        // GITHUB_APP_KEY_B64=LS0tLS1CRUdJTi... -- KEY in name catches it,
        // but also test the base64 catch-all pattern
        let input = "SOME_CONFIG=LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQ== \n";
        let output = redact_output(input);
        assert!(output.contains("[REDACTED]"), "got: {output}");
        assert!(
            !output.contains("LS0tLS1CRUdJTi"),
            "base64 value should be redacted, got: {output}"
        );
    }

    #[test]
    fn test_redact_standalone_base64_line() {
        // A line that's just a base64 blob (like a key file or cert body)
        let input = "LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQpNSUlFcEFJQkFBS0NBUUVB";
        let output = redact_output(input);
        assert!(output.contains("[REDACTED]"), "got: {output}");
    }

    #[test]
    fn test_redact_session_id_hex() {
        let input = "SESSION_ID=a3f8b1c2d4e5f6a7b8c9d0e1f2a3b4c5 \n";
        let output = redact_output(input);
        assert!(output.contains("[REDACTED]"), "got: {output}");
    }

    #[test]
    fn test_no_false_positive_short_values() {
        // Short normal values should NOT be redacted
        let input = "HOME=/home/user \nPATH=/usr/bin \n";
        let output = redact_output(input);
        assert_eq!(output, input, "short values should not be redacted");
    }

    #[test]
    fn test_no_false_positive_numeric_values() {
        // Plain numbers shouldn't trigger
        let input = "PORT=8080 \nCOUNT=42 \n";
        let output = redact_output(input);
        assert_eq!(output, input, "numeric values should not be redacted");
    }
}
