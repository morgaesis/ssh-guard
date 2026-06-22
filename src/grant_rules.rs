//! Conservative static-rule synthesis for prose session grants.
//!
//! The compiler is intentionally domain-specific. Unknown prose still becomes
//! LLM session context, but it does not produce broad static globs.

use regex::Regex;
use std::collections::BTreeSet;
use std::sync::OnceLock;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CompiledGrantRules {
    pub allow: Vec<String>,
    pub deny: Vec<String>,
    pub notes: Vec<String>,
}

pub fn compile_session_grant_rules(prose: &str) -> CompiledGrantRules {
    let mut compiled = CompiledGrantRules::default();
    compile_backtick_examples(prose, &mut compiled);
    compile_kubernetes_grant(prose, &mut compiled);
    compiled
}

fn compile_backtick_examples(prose: &str, compiled: &mut CompiledGrantRules) {
    for capture in backtick_pattern().captures_iter(prose) {
        let Some(command) = capture.get(1).map(|m| m.as_str().trim()) else {
            continue;
        };
        if command.is_empty()
            || looks_dangerous_static_command(command)
            || !looks_like_command(command)
        {
            continue;
        }
        push_unique(&mut compiled.allow, command.to_string());
    }
    if !compiled.allow.is_empty() {
        compiled
            .notes
            .push("exact backtick command examples were added as static allows".to_string());
    }
}

fn compile_kubernetes_grant(prose: &str, compiled: &mut CompiledGrantRules) {
    let lower = prose.to_ascii_lowercase();
    if !mentions_kubernetes(&lower) {
        return;
    }

    add_shell_control_denies(&mut compiled.deny);
    add_kubernetes_secret_and_escape_denies(&mut compiled.deny);

    let namespaces = infer_namespaces(prose);
    let contexts = infer_contexts(prose);
    let prefixes = kubectl_prefixes(&contexts);

    add_cluster_read_allows(&prefixes, &mut compiled.allow);

    if namespaces.is_empty() {
        compiled.notes.push(
            "kubernetes prose was recognized, but no namespace was inferred; static resource allows were not broadened".to_string(),
        );
        return;
    }

    for namespace in &namespaces {
        add_namespaced_kubernetes_read_allows(&prefixes, namespace, &mut compiled.allow);
        if wants_replica_scaling(&lower) {
            add_namespaced_scale_allows(&prefixes, namespace, &mut compiled.allow);
        }
        if wants_ingress_or_proxy_writes(&lower) {
            add_namespaced_reverse_proxy_allows(&prefixes, namespace, &mut compiled.allow);
        }
    }

    compiled.notes.push(format!(
        "generated kubernetes static rules for namespaces [{}]",
        namespaces.into_iter().collect::<Vec<_>>().join(", ")
    ));
}

fn mentions_kubernetes(lower: &str) -> bool {
    lower.contains("kubernetes")
        || lower.contains("kube ")
        || lower.contains("kube-")
        || lower.contains("kubectl")
        || lower.contains("k8s")
}

fn wants_replica_scaling(lower: &str) -> bool {
    lower.contains("replica")
        || lower.contains("scale")
        || lower.contains("scaling")
        || lower.contains("deployment")
        || lower.contains("statefulset")
}

fn wants_ingress_or_proxy_writes(lower: &str) -> bool {
    lower.contains("ingress")
        || lower.contains("reverse proxy")
        || lower.contains("reverse-proxy")
        || lower.contains("httproute")
        || lower.contains("gateway")
}

fn infer_namespaces(prose: &str) -> BTreeSet<String> {
    let mut namespaces = BTreeSet::new();
    for pattern in namespace_patterns() {
        for capture in pattern.captures_iter(prose) {
            if let Some(ns) = capture.get(1).map(|m| sanitize_kube_name(m.as_str())) {
                if is_valid_kube_name(&ns) {
                    namespaces.insert(ns);
                }
            }
        }
    }

    let lower = prose.to_ascii_lowercase();
    for known in ["nextcloud", "ingress-nginx", "traefik", "nginx"] {
        if lower.contains(known) {
            namespaces.insert(known.to_string());
        }
    }

    namespaces
}

fn infer_contexts(prose: &str) -> Vec<String> {
    let mut contexts = BTreeSet::new();
    for pattern in context_patterns() {
        for capture in pattern.captures_iter(prose) {
            if let Some(ctx) = capture.get(1).map(|m| sanitize_kube_name(m.as_str())) {
                if is_valid_kube_name(&ctx) {
                    contexts.insert(ctx);
                }
            }
        }
    }
    contexts.into_iter().collect()
}

fn kubectl_prefixes(contexts: &[String]) -> Vec<String> {
    let mut prefixes = vec!["kubectl".to_string()];
    for context in contexts {
        prefixes.push(format!("kubectl --context {}", context));
        prefixes.push(format!("kubectl --context={}", context));
    }
    prefixes
}

fn add_shell_control_denies(deny: &mut Vec<String>) {
    for pattern in ["*;*", "*&&*", "*||*", "*|*", "*>*", "*<*", "*`*", "*$(*"] {
        push_unique(deny, pattern.to_string());
    }
}

fn add_kubernetes_secret_and_escape_denies(deny: &mut Vec<String>) {
    for pattern in [
        "kubectl * secret*",
        "kubectl get secret*",
        "kubectl describe secret*",
        "kubectl edit secret*",
        "kubectl patch secret*",
        "kubectl delete secret*",
        "kubectl * create token*",
        "kubectl create token*",
        "kubectl * config view --raw*",
        "kubectl config view --raw*",
        "kubectl * exec *",
        "kubectl exec *",
        "kubectl * cp *",
        "kubectl cp *",
        "kubectl * port-forward *",
        "kubectl port-forward *",
        "kubectl * delete *",
        "kubectl delete *",
    ] {
        push_unique(deny, pattern.to_string());
    }
}

fn add_cluster_read_allows(prefixes: &[String], allow: &mut Vec<String>) {
    for prefix in prefixes {
        for pattern in [
            format!("{prefix} config current-context"),
            format!("{prefix} config get-contexts"),
            format!("{prefix} get namespace*"),
            format!("{prefix} get ns*"),
        ] {
            push_unique(allow, pattern);
        }
    }
}

fn add_namespaced_kubernetes_read_allows(
    prefixes: &[String],
    namespace: &str,
    allow: &mut Vec<String>,
) {
    let resources = [
        "pods",
        "pod",
        "services",
        "service",
        "svc",
        "deployments",
        "deployment",
        "deploy",
        "statefulsets",
        "statefulset",
        "sts",
        "daemonsets",
        "daemonset",
        "ds",
        "replicasets",
        "replicaset",
        "rs",
        "ingress",
        "ingresses",
        "ing",
        "configmaps",
        "configmap",
        "cm",
        "events",
        "endpoints",
        "endpoint",
        "httproutes",
        "httproute",
        "gateways",
        "gateway",
    ];
    for prefix in prefixes {
        for resource in resources {
            add_namespaced_patterns(prefix, namespace, "get", resource, allow);
            add_namespaced_patterns(prefix, namespace, "describe", resource, allow);
        }
        push_unique(allow, format!("{prefix} logs * -n {namespace}"));
        push_unique(allow, format!("{prefix} logs * --namespace {namespace}"));
    }
}

fn add_namespaced_scale_allows(prefixes: &[String], namespace: &str, allow: &mut Vec<String>) {
    let resources = ["deployment", "deploy", "statefulset", "sts"];
    for prefix in prefixes {
        for resource in resources {
            push_unique(
                allow,
                format!("{prefix} scale {resource}/* --replicas=* -n {namespace}"),
            );
            push_unique(
                allow,
                format!("{prefix} scale {resource}/* --replicas=* --namespace {namespace}"),
            );
            push_unique(
                allow,
                format!("{prefix} scale {resource} * --replicas=* -n {namespace}"),
            );
            push_unique(
                allow,
                format!("{prefix} scale {resource} * --replicas=* --namespace {namespace}"),
            );
        }
    }
}

fn add_namespaced_reverse_proxy_allows(
    prefixes: &[String],
    namespace: &str,
    allow: &mut Vec<String>,
) {
    let verbs = ["edit", "patch", "annotate", "label"];
    let resources = [
        "ingress",
        "ingresses",
        "ing",
        "httproute",
        "httproutes",
        "gateway",
        "gateways",
    ];
    for prefix in prefixes {
        for verb in verbs {
            for resource in resources {
                add_namespaced_patterns(prefix, namespace, verb, resource, allow);
            }
        }
    }
}

fn add_namespaced_patterns(
    prefix: &str,
    namespace: &str,
    verb: &str,
    resource: &str,
    allow: &mut Vec<String>,
) {
    push_unique(allow, format!("{prefix} -n {namespace} {verb} {resource}"));
    push_unique(
        allow,
        format!("{prefix} -n {namespace} {verb} {resource}/*"),
    );
    push_unique(
        allow,
        format!("{prefix} --namespace {namespace} {verb} {resource}"),
    );
    push_unique(
        allow,
        format!("{prefix} --namespace {namespace} {verb} {resource}/*"),
    );
    push_unique(allow, format!("{prefix} {verb} {resource} -n {namespace}"));
    push_unique(
        allow,
        format!("{prefix} {verb} {resource}/* -n {namespace}"),
    );
    push_unique(
        allow,
        format!("{prefix} {verb} {resource} * -n {namespace}"),
    );
    push_unique(
        allow,
        format!("{prefix} {verb} {resource} --namespace {namespace}"),
    );
    push_unique(
        allow,
        format!("{prefix} {verb} {resource}/* --namespace {namespace}"),
    );
    push_unique(
        allow,
        format!("{prefix} {verb} {resource} * --namespace {namespace}"),
    );
}

fn sanitize_kube_name(value: &str) -> String {
    value
        .trim_matches(|ch: char| !ch.is_ascii_alphanumeric() && ch != '-' && ch != '_')
        .trim_end_matches(|ch: char| matches!(ch, '.' | ',' | ';' | ':' | ')' | ']'))
        .to_ascii_lowercase()
}

fn is_valid_kube_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 253
        && value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' || ch == '.')
}

fn looks_like_command(value: &str) -> bool {
    let first = value.split_whitespace().next().unwrap_or_default();
    !first.is_empty()
        && first
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.' | '/' | '\\'))
}

fn looks_dangerous_static_command(command: &str) -> bool {
    let lower = command.to_ascii_lowercase();
    lower.contains(';')
        || lower.contains('|')
        || lower.contains("&&")
        || lower.contains("||")
        || lower.contains('>')
        || lower.contains('<')
        || lower.contains('`')
        || lower.contains("$(")
        || lower.contains(" rm -rf")
        || lower.starts_with("rm -rf")
        || lower.contains("/etc/shadow")
        || lower.contains(" secret")
        || lower.contains(" secrets")
}

fn push_unique(values: &mut Vec<String>, value: String) {
    if !values.iter().any(|existing| existing == &value) {
        values.push(value);
    }
}

fn namespace_patterns() -> &'static [Regex] {
    static PATTERNS: OnceLock<Vec<Regex>> = OnceLock::new();
    PATTERNS
        .get_or_init(|| {
            vec![
                Regex::new(r"(?i)\bnamespace(?:s)?\s+([a-z0-9][a-z0-9_.-]{0,252})").unwrap(),
                Regex::new(r"(?i)\bns\s+([a-z0-9][a-z0-9_.-]{0,252})").unwrap(),
                Regex::new(r"(?i)(?:^|\s)-n\s+([a-z0-9][a-z0-9_.-]{0,252})").unwrap(),
                Regex::new(r"(?i)--namespace(?:=|\s+)([a-z0-9][a-z0-9_.-]{0,252})").unwrap(),
            ]
        })
        .as_slice()
}

fn context_patterns() -> &'static [Regex] {
    static PATTERNS: OnceLock<Vec<Regex>> = OnceLock::new();
    PATTERNS
        .get_or_init(|| {
            vec![
                Regex::new(r"(?i)\b([a-z0-9][a-z0-9_.-]{1,252})\s+(?:kube|kubernetes)\s+cluster\b")
                    .unwrap(),
                Regex::new(r"(?i)\bcontext\s+([a-z0-9][a-z0-9_.-]{1,252})").unwrap(),
                Regex::new(r"(?i)--context(?:=|\s+)([a-z0-9][a-z0-9_.-]{1,252})").unwrap(),
            ]
        })
        .as_slice()
}

fn backtick_pattern() -> &'static Regex {
    static PATTERN: OnceLock<Regex> = OnceLock::new();
    PATTERN.get_or_init(|| Regex::new(r"`([^`\r\n]+)`").unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nextcloud_kubernetes_grant_generates_narrow_static_rules() {
        let compiled = compile_session_grant_rules(
            "readonly access to the nextcloud stuff in the morgaesis-dev kube cluster, not the secrets, and write access to scaling replicas and editing ingresses",
        );

        assert!(compiled
            .deny
            .iter()
            .any(|pattern| pattern == "kubectl * secret*"));
        assert!(compiled
            .allow
            .iter()
            .any(|pattern| pattern == "kubectl -n nextcloud get pods"));
        assert!(compiled
            .allow
            .iter()
            .any(|pattern| pattern == "kubectl --context morgaesis-dev -n nextcloud get pods"));
        assert!(compiled
            .allow
            .iter()
            .any(|pattern| pattern == "kubectl scale deployment/* --replicas=* -n nextcloud"));
        assert!(compiled
            .allow
            .iter()
            .any(|pattern| pattern == "kubectl -n nextcloud edit ingress"));
        assert!(!compiled
            .allow
            .iter()
            .any(|pattern| pattern.contains("nextcloud*")));
    }

    #[test]
    fn kubernetes_without_namespace_stays_conservative() {
        let compiled = compile_session_grant_rules("readonly access to a kubernetes cluster");
        assert!(compiled
            .allow
            .iter()
            .any(|pattern| pattern == "kubectl config current-context"));
        assert!(!compiled
            .allow
            .iter()
            .any(|pattern| pattern == "kubectl get pods*"));
        assert!(compiled
            .notes
            .iter()
            .any(|note| note.contains("no namespace was inferred")));
    }

    #[test]
    fn generic_cluster_language_does_not_trigger_kubernetes_rules() {
        let compiled = compile_session_grant_rules("readonly access to a postgres cluster");
        assert!(compiled.allow.is_empty());
        assert!(compiled.deny.is_empty());
    }

    #[test]
    fn safe_backtick_examples_become_exact_allows() {
        let compiled = compile_session_grant_rules("Allow `opnsense-api system status` please.");
        assert_eq!(compiled.allow, vec!["opnsense-api system status"]);
    }

    #[test]
    fn dangerous_backtick_examples_are_not_allowed() {
        let compiled = compile_session_grant_rules("Never add `sh -c 'id; rm -rf /'`.");
        assert!(compiled.allow.is_empty());
    }
}
