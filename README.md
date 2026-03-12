# ssh-guard

SSH wrapper that sends every command to an LLM for approval before execution. Give your AI agents SSH access without giving them the keys to the kingdom.

```
$ ssh-guard prod-server 'ls -la /etc/nginx/'
drwxr-xr-x 8 root root 4096 Mar 10 14:22 .
-rw-r--r-- 1 root root 1482 Mar 10 14:22 nginx.conf
...

$ ssh-guard prod-server 'rm -rf /etc/nginx/'
ssh-guard: DENIED (risk=9) - Recursive deletion of system config directory.
```

Zero output on approval. Denied commands print the reason and risk score.

![ssh-guard demo](./docs/demo.svg)

## Why

AI agents (Claude Code, Aider, OpenHands, CrewAI, LangChain, etc.) increasingly need SSH access to remote servers for debugging, log analysis, and ops tasks. But a single hallucinated `rm -rf` or `kubectl delete namespace` can take down production.

ssh-guard sits between the agent and SSH. Every command gets evaluated by a fast, cheap LLM call (Gemini Flash by default via OpenRouter, ~0.001c per decision) before it reaches the server. Approved commands run silently. Denied commands return an error with explanation.

## Install

```bash
curl -fsSL https://raw.githubusercontent.com/morgaesis/ssh-guard/main/install.sh | bash
```

Or build from source: `cargo install --path .`

See [INSTALL.md](INSTALL.md) for all options (manual download, specific versions, provider setup, agent integration).

## Quick start

```bash
# Set your API key (OpenRouter, or any OpenAI-compatible endpoint)
export SSH_GUARD_API_KEY="your-key-here"
# Or: export OPENROUTER_API_KEY="your-key-here"

# Use it like ssh
ssh-guard myserver 'uptime'
ssh-guard myserver 'cat /var/log/syslog'
ssh-guard myserver 'sudo systemctl status nginx'

# These will be denied in readonly mode:
ssh-guard myserver 'rm -rf /tmp/*'
ssh-guard myserver 'systemctl restart nginx'
```

## Modes

Three built-in policies, set via `SSH_GUARD_MODE`:

| Mode | Default | Use case |
|------|---------|----------|
| `readonly` | Yes | Agents that only need to observe. Blocks all writes, installs, service changes. |
| `paranoid` | | Like readonly, but also blocks reading file contents, env vars, logs. Only structural metadata (ls, ps, df, etc). Prevents secret exfiltration. |
| `safe` | | Agents that need to do work. Allows targeted writes and service restarts, blocks destructive/broad operations (rm -rf, reboot, kubectl delete namespace). |

```bash
SSH_GUARD_MODE=safe ssh-guard server 'systemctl restart myapp'  # allowed
SSH_GUARD_MODE=paranoid ssh-guard server 'cat /etc/passwd'      # denied
```

All modes evaluate `sudo` by the underlying command, not the keyword itself:
```
sudo ls /etc/nginx/        -> readonly: allowed (read operation)
sudo rm -rf /etc/nginx/    -> readonly: denied  (write operation)
sudo systemctl restart app -> safe: allowed      (targeted restart)
```

## Configuration

All configuration via environment variables or `.env` files.

ssh-guard walks up from your current directory to `/` looking for `.env` files (closest wins), so you can scope config per project.

| Variable | Default | Description |
|----------|---------|-------------|
| `SSH_GUARD_API_KEY` | `$OPENROUTER_API_KEY` | LLM API key (required) |
| `SSH_GUARD_API_URL` | `https://openrouter.ai/api/v1/chat/completions` | Any OpenAI-compatible endpoint |
| `SSH_GUARD_MODEL` | `google/gemini-2.0-flash-001` | Model for command evaluation |
| `SSH_GUARD_API_TYPE` | `openai` | `openai` or `anthropic` |
| `SSH_GUARD_MODE` | `readonly` | `readonly`, `paranoid`, or `safe` |
| `SSH_GUARD_PROMPT` | (per mode) | Custom system prompt (overrides mode) |
| `SSH_GUARD_PASSTHROUGH` | (none) | Always-allow commands, comma-separated |
| `SSH_GUARD_LOG` | (none) | Audit log file path |
| `SSH_GUARD_REDACT` | `true` | Redact secrets from command output |
| `SSH_GUARD_SSH_BIN` | `/usr/bin/ssh` | Path to real ssh binary |
| `SSH_GUARD_TIMEOUT` | `30` | LLM call timeout (seconds) |
| `SSH_GUARD_MAX_TOKENS` | `512` | Max LLM response tokens |

See [`.env.example`](.env.example) for a copyable template.

## Agent integration

Point your agent's SSH command at `ssh-guard` instead of `ssh`.

<details>
<summary><b>Claude Code (CLAUDE.md)</b></summary>

```markdown
# SSH Access
Use `ssh-guard` instead of `ssh` for all remote commands.
Never use interactive SSH sessions.
```

</details>

<details>
<summary><b>OpenHands / SWE-Agent</b></summary>

```bash
# In agent config or sandbox setup
export SSH_GUARD_API_KEY="..."
export SSH_GUARD_MODE=readonly
alias ssh=ssh-guard
```

</details>

<details>
<summary><b>LangChain / CrewAI tool definition</b></summary>

```python
import subprocess

def ssh_command(host: str, command: str) -> str:
    """Execute a command on a remote host via ssh-guard."""
    result = subprocess.run(
        ["ssh-guard", host, command],
        capture_output=True, text=True, timeout=60,
        env={**os.environ, "SSH_GUARD_MODE": "readonly"}
    )
    if result.returncode != 0:
        return f"DENIED: {result.stderr.strip()}"
    return result.stdout
```

</details>

<details>
<summary><b>Generic: alias ssh to ssh-guard</b></summary>

```bash
# In the agent's shell init or .env
alias ssh=ssh-guard
export SSH_GUARD_API_KEY="..."
```

</details>

## Output redaction

When `SSH_GUARD_REDACT=true` (default), command output is filtered through pattern-based redaction before reaching the agent:

```
DB_PASSWORD=hunter2         ->  DB_PASSWORD=[REDACTED]
export API_TOKEN="sk-..."   ->  export API_TOKEN="[REDACTED]"
-----BEGIN PRIVATE KEY----  ->  -----BEGIN PRIVATE KEY---- [REDACTED]
```

Patterns matched: `*_TOKEN`, `*_KEY`, `*_SECRET`, `*_PASSWORD`, `*_CREDENTIAL`, `bearer`, PEM blocks, `sk-*` prefixed strings, JWTs.

## Audit logging

```bash
export SSH_GUARD_LOG=/var/log/ssh-guard.log
```

Logs denials always. Logs approvals only when risk score >= 4. Format:
```
[2025-03-12T14:22:01+00:00] DENIED risk=9 cmd=rm -rf / reason=Recursive deletion of root filesystem
[2025-03-12T14:22:15+00:00] APPROVED risk=4 cmd=sudo cat /etc/hosts reason=Reading system config file
```

## Limitations

Be honest about what this is and isn't:

- **Not a sandbox.** ssh-guard is a policy gate, not an isolation boundary. A sufficiently creative command chain might get past the LLM. Use it as defense-in-depth alongside proper IAM, restricted users, and network segmentation.
- **No interactive sessions.** Agents get command execution only. Humans should use `ssh` directly.
- **LLM latency.** Each command adds ~0.5-2s for the LLM call. Use `SSH_GUARD_PASSTHROUGH` for commands you know are safe to skip the check.
- **Fail-closed.** If the LLM call fails or returns unparseable output, the command is denied.

## Recording a demo

A [VHS tape file](./demo.tape) is included for generating the terminal recording:

```bash
# Install VHS: https://github.com/charmbracelet/vhs
vhs demo.tape  # produces docs/demo.svg
```

## License

MIT
