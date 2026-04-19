//! In-memory session grant registry.
//!
//! A session is an opaque token the caller includes in `ExecuteRequest`.
//! Grants attach extra allow/deny glob patterns to that token. Session
//! denies short-circuit to DENY before the evaluator. Session allows
//! short-circuit to ALLOW before the evaluator, letting an operator
//! hand a specific agent narrow extra permissions (e.g. "mkdir
//! /tmp/work/*", "rm /tmp/work/scratch.txt") without relaxing the
//! global mode.
//!
//! Grants are in-memory only. They clear on daemon restart, matching
//! the "short-lived extra trust" semantics of sudo timestamps.

use guard::policy::{Decision, PolicyRule};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionGrant {
    pub allow: Vec<String>,
    pub deny: Vec<String>,
    /// Unix seconds after which this grant is treated as absent.
    pub expires_at: Option<u64>,
    /// Free-form text appended to the LLM system prompt for evaluator
    /// calls made under this session token. Use to give the model
    /// context the static glob patterns cannot express, e.g. "this
    /// session is restoring a Postgres backup; treat pg_restore and
    /// related psql copy commands as expected".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prompt_append: Option<String>,
}

impl SessionGrant {
    pub fn is_expired(&self, now: u64) -> bool {
        matches!(self.expires_at, Some(exp) if now >= exp)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionDecision {
    Allow,
    Deny,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionGrantSummary {
    pub token: String,
    pub allow: Vec<String>,
    pub deny: Vec<String>,
    pub expires_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prompt_append: Option<String>,
}

#[derive(Debug, Default)]
pub struct SessionRegistry {
    grants: HashMap<String, SessionGrant>,
}

impl SessionRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn grant(&mut self, token: String, grant: SessionGrant) {
        self.grants.insert(token, grant);
    }

    pub fn revoke(&mut self, token: &str) -> bool {
        self.grants.remove(token).is_some()
    }

    pub fn list(&self) -> Vec<SessionGrantSummary> {
        let now = current_unix_secs();
        self.grants
            .iter()
            .filter(|(_, g)| !g.is_expired(now))
            .map(|(token, g)| SessionGrantSummary {
                token: token.clone(),
                allow: g.allow.clone(),
                deny: g.deny.clone(),
                expires_at: g.expires_at,
                prompt_append: g.prompt_append.clone(),
            })
            .collect()
    }

    /// Return the additive prompt for this session, if the grant exists,
    /// has not expired, and has a prompt attached.
    pub fn prompt_append_for(&self, token: &str) -> Option<String> {
        let grant = self.grants.get(token)?;
        if grant.is_expired(current_unix_secs()) {
            return None;
        }
        grant.prompt_append.clone()
    }

    /// Remove expired entries. Called opportunistically to keep the
    /// registry from growing indefinitely when tokens churn.
    pub fn purge_expired(&mut self) {
        let now = current_unix_secs();
        self.grants.retain(|_, g| !g.is_expired(now));
    }

    /// Check whether the session's grants short-circuit the decision.
    ///
    /// Returns `Some(Deny)` if a deny pattern matches — deny always wins.
    /// Returns `Some(Allow)` if an allow pattern matches.
    /// Returns `None` if the session has no matching rule (fall through
    /// to normal evaluation), including when the token is unknown,
    /// expired, or has no patterns.
    pub fn check(
        &self,
        token: &str,
        cmd: &str,
        args: &[String],
    ) -> Option<(SessionDecision, String)> {
        let grant = self.grants.get(token)?;
        if grant.is_expired(current_unix_secs()) {
            return None;
        }

        let full_cmd = if args.is_empty() {
            cmd.to_string()
        } else {
            format!("{} {}", cmd, args.join(" "))
        };

        let deny_rule = PolicyRule {
            patterns: grant.deny.clone(),
            decision: Decision::Deny,
            description: None,
        };
        if deny_rule.matches(&full_cmd) {
            let which = grant
                .deny
                .iter()
                .find(|p| {
                    PolicyRule {
                        patterns: vec![(*p).clone()],
                        decision: Decision::Deny,
                        description: None,
                    }
                    .matches(&full_cmd)
                })
                .cloned()
                .unwrap_or_else(|| "<unknown>".to_string());
            return Some((
                SessionDecision::Deny,
                format!("session deny pattern: {}", which),
            ));
        }

        let allow_rule = PolicyRule {
            patterns: grant.allow.clone(),
            decision: Decision::Allow,
            description: None,
        };
        if allow_rule.matches(&full_cmd) {
            let which = grant
                .allow
                .iter()
                .find(|p| {
                    PolicyRule {
                        patterns: vec![(*p).clone()],
                        decision: Decision::Allow,
                        description: None,
                    }
                    .matches(&full_cmd)
                })
                .cloned()
                .unwrap_or_else(|| "<unknown>".to_string());
            return Some((
                SessionDecision::Allow,
                format!("session allow pattern: {}", which),
            ));
        }

        None
    }
}

fn current_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reg_with(token: &str, allow: &[&str], deny: &[&str]) -> SessionRegistry {
        let mut reg = SessionRegistry::new();
        reg.grant(
            token.to_string(),
            SessionGrant {
                allow: allow.iter().map(|s| s.to_string()).collect(),
                deny: deny.iter().map(|s| s.to_string()).collect(),
                expires_at: None,
                prompt_append: None,
            },
        );
        reg
    }

    #[test]
    fn unknown_token_returns_none() {
        let reg = reg_with("tok", &["mkdir*"], &[]);
        assert!(reg.check("other", "mkdir", &["/tmp/x".into()]).is_none());
    }

    #[test]
    fn allow_pattern_matches() {
        let reg = reg_with("tok", &["mkdir /tmp/work/*"], &[]);
        let hit = reg
            .check("tok", "mkdir", &["/tmp/work/out".into()])
            .expect("allow should match");
        assert_eq!(hit.0, SessionDecision::Allow);
    }

    #[test]
    fn deny_wins_over_allow() {
        let reg = reg_with("tok", &["rm*"], &["rm -rf /*"]);
        let hit = reg
            .check("tok", "rm", &["-rf".into(), "/".into()])
            .expect("deny should match");
        assert_eq!(hit.0, SessionDecision::Deny);
    }

    #[test]
    fn no_match_returns_none_even_with_grants() {
        let reg = reg_with("tok", &["mkdir*"], &["rm*"]);
        assert!(reg.check("tok", "ls", &["-la".into()]).is_none());
    }

    #[test]
    fn expired_grant_is_ignored() {
        let mut reg = SessionRegistry::new();
        reg.grant(
            "tok".to_string(),
            SessionGrant {
                allow: vec!["mkdir*".to_string()],
                deny: vec![],
                expires_at: Some(1), // 1970-01-01 +1s
                prompt_append: None,
            },
        );
        assert!(reg.check("tok", "mkdir", &["/tmp".into()]).is_none());
    }

    #[test]
    fn revoke_removes_grant() {
        let mut reg = reg_with("tok", &["mkdir*"], &[]);
        assert!(reg.revoke("tok"));
        assert!(reg.check("tok", "mkdir", &["/tmp".into()]).is_none());
        assert!(!reg.revoke("tok"));
    }

    #[test]
    fn prompt_append_returned_for_live_grant() {
        let mut reg = SessionRegistry::new();
        reg.grant(
            "tok".to_string(),
            SessionGrant {
                allow: vec![],
                deny: vec![],
                expires_at: None,
                prompt_append: Some("session is restoring a backup".to_string()),
            },
        );
        assert_eq!(
            reg.prompt_append_for("tok").as_deref(),
            Some("session is restoring a backup")
        );
        assert!(reg.prompt_append_for("missing").is_none());
    }

    #[test]
    fn prompt_append_suppressed_for_expired_grant() {
        let mut reg = SessionRegistry::new();
        reg.grant(
            "tok".to_string(),
            SessionGrant {
                allow: vec![],
                deny: vec![],
                expires_at: Some(1),
                prompt_append: Some("ignored".to_string()),
            },
        );
        assert!(reg.prompt_append_for("tok").is_none());
    }

    #[test]
    fn list_returns_non_expired() {
        let mut reg = SessionRegistry::new();
        reg.grant(
            "live".to_string(),
            SessionGrant {
                allow: vec!["*".into()],
                deny: vec![],
                expires_at: None,
                prompt_append: None,
            },
        );
        reg.grant(
            "dead".to_string(),
            SessionGrant {
                allow: vec!["*".into()],
                deny: vec![],
                expires_at: Some(1),
                prompt_append: None,
            },
        );
        let listed = reg.list();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].token, "live");
    }
}
