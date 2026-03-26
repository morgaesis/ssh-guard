# Guard Roadmap

## Overview

Guard is a secret broker and command policy enforcement tool for AI agents.

**Core principle:** Agents never receive raw secrets. Policy blocks dangerous actions.

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        guard-core                                │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐       │
│  │   Policy    │  │   Secret    │  │    Audit     │       │
│  │   Engine    │  │   Broker    │  │    Logger    │       │
│  └──────────────┘  └──────────────┘  └──────────────┘       │
└─────────────────────────────────────────────────────────────────┘
           │                    │                    │
           ▼                    ▼                    ▼
    ┌───────────┐        ┌───────────┐        ┌───────────┐
    │ guard run │        │guard proxy│        │guard shim │
    │   (CLI)   │        │   (LLM)   │        │ generator │
    └───────────┘        └───────────┘        └───────────┘
```

## Implemented Features

### CLI Mode (`guard run`)
- [x] Command execution with policy checks
- [x] Secret injection via FD
- [x] Output redaction

### LLM Proxy (`guard proxy`)
- [x] HTTP server (hyper)
- [x] OpenAI-compatible endpoints (/chat/completions, /completions)
- [x] Request redaction
- [x] Response redaction
- [x] SSE/NDJSON streaming support

### Policy Engine
- [x] Command allow/deny lists
- [x] Glob pattern matching
- [x] Policy groups with priority
- [x] YAML configuration
- [x] Default-deny behavior

### Secret Broker
- [x] `pass` backend (unix password store)
- [x] Environment backend (dev/testing)
- [x] Local YAML backend (GPG encrypted)
- [x] SecretFd for FD-based injection
- [x] SecretManager with caching

### Output Redaction
- [x] Pattern-based redaction
- [x] Built-in patterns for API keys, AWS keys, passwords, tokens, PEM keys
- [x] RedactingWriter for streaming
- [x] Configurable patterns

### Shim Generator
- [x] Generate shims for common tools
- [x] PATH prepend integration
- [x] Tools: ssh, scp, sftp, curl, wget, aws, kubectl, docker, git

### Git Hook Integration
- [x] Pre-commit hook
- [x] Pre-push hook
- [x] Staged file scanning
- [x] Commit scanning
- [x] Secret detection

## Remaining Features

### Secret Backends
- [ ] `vault` backend (HashiCorp Vault)
- [ ] `aws-ssm` backend (AWS SSM Parameter Store)
- [ ] `gopass` backend

### Privileged SSH Proxy (Server/Client Mode)

Agents often need to perform privileged operations (as root or other users) without having direct SSH access to those privileges. This feature enables a secure delegation model.

#### Architecture

```
┌─────────────┐       ┌──────────────────┐       ┌─────────────────┐
│   Agent     │──────▶│  ssh-guard       │──────▶│  Target Host    │
│ (untrusted) │  IPC  │  Server (trusted) │  SSH  │ (privileged)    │
└─────────────┘       └──────────────────┘       └─────────────────┘
                              │
                              │ SSH key stored on
                              │ server (not agent)
```

#### Modes

1. **Client Mode (default)**: Current behavior - ssh-guard wraps local SSH commands
2. **Server Mode**: ssh-guard runs as a daemon/service that agents connect to via CLI or IPC
3. **ProxyJump Mode**: ssh-guard acts as a jump host, routing SSH through the trusted server

#### Server Mode Behavior

- Agent connects to `ssh-guard server` (local or remote via SSH tunnel)
- Agent sends: `{target: "prod-server", command: "systemctl restart nginx"}`
- ssh-guard server evaluates policy, executes with privileged credentials
- Output streamed back to agent

#### Implementation Phases

- [ ] `guard server` subcommand - daemon mode accepting command requests
- [ ] IPC protocol (UNIX socket or TCP)
- [ ] Privileged credential storage (server-side SSH keys, sudo)
- [ ] `guard connect` subcommand - agent-side client to connect to server
- [ ] ProxyJump integration for seamless SSH routing
- [ ] Connection multiplexing for performance

## Security Model

| Threat | Defense |
|--------|---------|
| Read secrets from files | Policy blocks `cat ~/.env`, `cat ~/.aws/*` |
| Network exfil | Policy blocks `curl`, `wget`, `nc` |
| SSH key exfil | Guard injects via FD, blocks `cat ~/.ssh/*` |
| Hardcoded secrets | Agent never has secrets to write |
| Git commits | Agent never has secrets to commit |
| Clipboard | Policy blocks `xclip`, `pbcopy` |
| LLM API exfil | Proxy redacts secrets from requests/responses |

**Out of scope:**
- Memory scraping (requires namespace isolation)
- Screen capture

## CLI Interface

```bash
guard run <cmd> [args...]           # Execute with policy + secret injection
guard shim install [--path DIR]      # Generate shim scripts
guard secrets <subcmd>              # Manage secrets (add, list, remove)
guard proxy --port N --upstream URL # Start LLM proxy
guard git-hook <subcmd>             # Git hook management
```

## Configuration

```yaml
# ~/.config/guard/policy.yaml
policy:
  commands:
    allow:
      - ssh
      - kubectl
      - docker
    deny:
      - "rm -rf /*"

secret_backend: pass  # pass, env, local
```

## Running

```bash
# Install shims
guard shim install --path ~/.guard/shims

# Add secret
guard secrets add prod/ssh-key --value "$(cat ~/.ssh/id_rsa)"

# Run command with policy
guard run ssh prod-server

# Start LLM proxy
guard proxy --port 8080 --upstream https://api.openai.com/v1
```
