# Guard Architecture

## Overview

Guard is a secret broker and command policy enforcement tool for AI agents. It operates in two modes:

1. **CLI Mode (`guard run`)** - Intercepts and policies command execution
2. **Proxy Mode (`guard proxy`)** - Intercepts and policies LLM API calls

The core principle: **Agents never receive raw secrets. Policy blocks dangerous actions.**

## Core Components

```
┌─────────────────────────────────────────────────────────────────┐
│                        guard-core                                │
│                                                                  │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐         │
│  │   Policy    │  │   Secret    │  │    Audit     │         │
│  │   Engine    │  │   Broker    │  │    Logger    │         │
│  └──────────────┘  └──────────────┘  └──────────────┘         │
│                                                                  │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐         │
│  │   Config    │  │    Output    │  │  Execution   │         │
│  │   Manager   │  │   Redactor   │  │   Context    │         │
│  └──────────────┘  └──────────────┘  └──────────────┘         │
└─────────────────────────────────────────────────────────────────┘
           │                    │                    │
           ▼                    ▼                    ▼
    ┌───────────┐        ┌───────────┐        ┌───────────┐
    │ guard run │        │guard proxy│        │guard shim │
    │   (CLI)   │        │   (LLM)   │        │ generator │
    └───────────┘        └───────────┘        └───────────┘
```

## Data Flow

### CLI Mode (`guard run <cmd>`)

```
Agent: "ssh prod-server"
         │
         ▼
┌─────────────────┐
│   Guard shim    │  (if PATH includes guard-shims)
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Policy Check   │  ← Is "ssh" allowed?
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Secret Broker   │  ← Inject SSH key via FD (never in env)
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│   Execute       │  ← Run with injected secrets
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Output Filter  │  ← Redact any secrets in output
└─────────────────┘
```

### Proxy Mode (`guard proxy`)

```
Agent → LLM Provider
         │
         ▼
┌─────────────────┐
│  Guard Proxy    │  ← Local HTTP proxy (:8080)
└────────┬────────┘
         │
    ┌────┴────┐
    │         │
    ▼         ▼
┌───────┐ ┌────────┐
│ Check │ │ Redact │
│ Policy│ │ Request│
└───┬───┘ └───┬────┘
    │         │
    ▼         ▼
┌─────────────────┐
│  LLM Provider   │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Redact Response│  ← Remove secrets before agent sees
└─────────────────┘
```

## Security Model

### Principle: Agent Never Has Secrets

1. Secrets stored in guard's secret backend (pass, vault, etc.)
2. Guard injects secrets via file descriptors or env at exec time
3. Agent process never sees raw secret values
4. If agent can't read secrets, it can't leak them

### Policy Engine

Policy is applied at two points:

| Mode | Policy Applied To |
|------|------------------|
| CLI | Commands (`ssh`, `curl`, `cat`, etc.) |
| Proxy | API request/response content |

### Threat Coverage

| Threat | Defense |
|--------|---------|
| Read secrets from files | Policy blocks `cat ~/.env`, `cat ~/.aws/*` |
| Network exfil | Policy blocks `curl`, `wget`, `nc` |
| SSH key exfil | Guard injects via FD, blocks `cat ~/.ssh/*` |
| Hardcoded secrets | Agent never has secrets to write |
| Git commits | Agent never has secrets to commit |

**Out of scope:**
- Memory scraping (requires namespace isolation)
- Screen capture
- Clipboard (OS-level)

## Components

### Policy Engine

```rust
pub struct PolicyEngine {
    rules: Vec<PolicyRule>,
    secret_patterns: Vec<Regex>,
}

impl PolicyEngine {
    pub fn check_command(&self, cmd: &str, args: &[String]) -> PolicyResult;
    pub fn check_content(&self, content: &str) -> PolicyResult;
}
```

### Secret Broker

```rust
pub trait SecretBackend: Send + Sync {
    async fn get(&self, key: &str) -> Result<Option<String>>;
    async fn inject_fd(&self, key: &str) -> Result<SecretFd>;
}

pub enum SecretFd {
    File { path: PathBuf, mode: u32 },
    Socket { path: PathBuf },
}
```

### Output Redactor

```rust
pub struct OutputRedactor {
    patterns: Vec<Regex>,
}

impl OutputRedactor {
    pub fn redact(&self, content: &str) -> String;
}
```

## CLI Interface

```bash
guard run <cmd> [args...]          # Execute with policy + secret injection
guard shim install [--path DIR]     # Generate shim scripts
guard secrets <subcmd>              # Manage secrets
guard proxy [--port N]             # Start LLM proxy
guard config <subcmd>              # Config management
guard policy <subcmd>              # Policy management
```

## Configuration

```yaml
policy:
  # Commands policy (CLI mode)
  commands:
    allow:
      - ssh
      - scp
      - kubectl
      - docker
    deny:
      - "rm -rf /*"
      - "*sudo*"

  # Secret patterns (used for redaction)
  secret_patterns:
    - "AWS_ACCESS_KEY_ID=[^\\s]+"
    - "password[:=][^\\s]+"
    - "sk-[a-zA-Z0-9]{20,}"

secret_backend: pass  # pass, vault, aws-ssm, gopass, local

execution:
  output_redact: true
  inject_secrets_via: fd  # fd or env
```

## Deployment

### Same-User Mode (Default)

```bash
guard run ssh prod-server
# Agent and guard run as same user
# Agent gets secrets via guard injection, never raw values
```

### Isolated Mode

```bash
guard run --isolated python agent.py
# Uses namespace isolation for additional protection
# Requires unshare/capabilities
```

## Audit

All events logged:

```
[2024-03-22T10:00:00Z] ALLOW cmd=ssh args=[prod-server]
[2024-03-22T10:00:05Z] DENY cmd=cat args=[~/.aws/credentials]
[2024-03-22T10:00:10Z] ALLOW cmd=curl args=[https://api.github.com]
[2024-03-22T10:00:15Z] REDACT pattern=AWS_KEY output
```
