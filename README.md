# guard

LLM-evaluated command gate for AI agents. Every command gets evaluated by a fast LLM call before execution. Approved commands run normally. Denied commands return an explanation.

```
$ guard run ls -la /etc/nginx/
drwxr-xr-x 8 root root 4096 Mar 10 14:22 .
-rw-r--r-- 1 root root 1482 Mar 10 14:22 nginx.conf

$ guard run rm -rf /etc/nginx/
DENIED: Recursive deletion of system config directory.
```

## Why

AI agents (Claude Code, Codex, Aider, OpenHands, CrewAI, etc.) increasingly need command execution access for debugging, log analysis, and ops tasks. A single hallucinated `rm -rf` or `kubectl delete namespace` can take down production.

Guard sits between the agent and the shell. Every command gets evaluated by an LLM (`openai/gpt-5.4-nano` via OpenRouter by default) before it reaches the system. The LLM analyzes intent and risk, not just pattern matching, so it catches obfuscated attacks and novel command chains that static policies miss.

Cost is negligible: each evaluation uses roughly 3600 prompt + 45 completion tokens, costing about $0.0005 per decision with `openai/gpt-5.4-nano`. A full 45-case CTF adversarial benchmark runs for about $0.02 total.

## Install

```bash
cargo install --path .
```

Or download a release artifact and install the binary manually.

See [INSTALL.md](INSTALL.md) for install options and [DEPLOYMENT.md](DEPLOYMENT.md) for service deployment.

## Quick start

```bash
# Set your API key (OpenRouter, or any OpenAI-compatible endpoint)
export SSH_GUARD_LLM_API_KEY="your-key-here"

# Start the server
guard server start &

# Execute commands through the guard
guard run uptime
guard run cat /var/log/syslog
guard run ps aux

# These will be denied:
guard run rm -rf /tmp/*
guard run sudo su
```

## Modes

Set via `SSH_GUARD_MODE`:

| Mode | Description |
|---|---|
| `default` | Balanced. Blocks destructive operations, privilege escalation, reverse shells, and obfuscated payloads. Allows routine admin commands like `ls`, `ps`, `cat`, `grep`, `df`. |
| `safe` | Permissive. Only blocks commands with clear destructive or escalation intent. Relies on architectural defenses (`env_clear`, output redaction) for secret protection. Allows reading any file. |
| `paranoid` | Restrictive. Blocks writes, sensitive file reads, network connections, shells, interpreters, and chained commands. Only allows basic read-only inspection (`id`, `hostname`, `uname`, `ls`, `ps`, `df`). |

```bash
SSH_GUARD_MODE=safe guard run cat /etc/shadow     # allowed (output redacted)
SSH_GUARD_MODE=paranoid guard run cat /etc/shadow  # denied
```

All modes evaluate `sudo` by the underlying command:

```bash
guard run sudo ls /etc/nginx/        # default: allowed (read operation)
guard run sudo rm -rf /etc/nginx/    # default: denied  (destructive)
guard run sudo systemctl restart app # safe: allowed     (targeted restart)
```

## Configuration

### Defaults vs. opt-ins

Guard ships with an LLM-only evaluation pipeline: a single call to
`openai/gpt-5.4-nano` via OpenRouter, function-calling based, with two retries
before failing closed. No static allow or deny lists are loaded. No fallback
model chain is active. This default is production-ready for the common case.

Two opt-in features exist for deployments with specific constraints:

- **Static allow/deny lists** via `--policy <yaml>`. Short-circuits the LLM
  for deterministic safe or unsafe patterns. See
  [`examples/`](examples/README.md) for `allow-policy.yaml`,
  `deny-policy.yaml`, and `hybrid-policy.yaml`.
- **Fallback model chain** via `SSH_GUARD_LLM_MODELS`. Fails over to
  alternate providers after the primary exhausts its retries. See
  [`examples/fallback-models.env`](examples/fallback-models.env).

Enable either only when a concrete latency or uptime constraint forces it.

### Environment variables

All configuration via environment variables, CLI flags, or `.env` files.

Guard walks up from your current directory to `/` looking for `.env` files (closest wins), so you can scope config per project.

| Variable | Default | Description |
|---|---|---|
| `SSH_GUARD_LLM_API_KEY` / `OPENROUTER_API_KEY` | (none) | LLM API key (required). `OPENROUTER_API_KEY` is the conventional name and is accepted for compatibility. |
| `SSH_GUARD_API_URL` | `https://openrouter.ai/api/v1/chat/completions` | Any OpenAI-compatible endpoint |
| `SSH_GUARD_LLM_MODELS` | (unset) | Optional comma-separated fallback chain (e.g. `openai/gpt-5.4-nano,meta-llama/llama-4-maverick`). When set, overrides `--llm-model` and is tried in order, each with its own retry budget. Primary model when unset: `openai/gpt-5.4-nano`. |
| `SSH_GUARD_LLM_RETRIES` | `2` | Retries per model on transient failures (429, timeouts, parse errors). 1-2. |
| `SSH_GUARD_MODE` | `default` | `default`, `safe`, or `paranoid` |
| `SSH_GUARD_PROMPT_APPEND` | (none) | Path to additive prompt file (appended to base prompt) |
| `SSH_GUARD_GPG_ID` | (none) | GPG key ID for secret encryption |
| `SSH_GUARD_BACKEND` | (auto) | Secret backend (`file`, `gpg`) |

The primary model is `openai/gpt-5.4-nano` via OpenRouter by default. Set it
per-invocation with `--llm-model <slug>`. To configure a true fallback chain
across providers, use `SSH_GUARD_LLM_MODELS` (comma-separated) or
`--llm-models`. `--llm-timeout <seconds>` controls the per-call HTTP timeout.

See [`.env.example`](.env.example) for a copyable template.

## Examples

### Basic server with default mode

Start the guard server and execute commands through it:

```bash
export SSH_GUARD_LLM_API_KEY="sk-or-v1-..."

guard server start --socket /tmp/guard.sock &
guard config set-server /tmp/guard.sock

# Allowed: routine inspection
guard run hostname
# guard-host

guard run ps aux
# USER  PID %CPU %MEM    VSZ   RSS TTY STAT START   TIME COMMAND
# root    1  0.0  0.0   4624  3456 ?   Ss   10:00   0:00 /sbin/init

# Denied: destructive
guard run rm -rf /
# DENIED: Recursive deletion of root filesystem

# Denied: obfuscated attack
guard run bash -c 'eval $(echo cm0gLXJmIC8= | base64 -d)'
# DENIED: Base64-decoded payload piped through eval
```

When using `guard server connect` directly (rather than `guard run`), put a
`--` separator between the target binary and its flags so clap does not
swallow them as `connect` options: `guard server connect --socket /tmp/guard.sock df -- -h`
works; `guard server connect --socket /tmp/guard.sock df -h` reports a
misleading "No server configured" error.

### Safe mode with output redaction

Safe mode allows almost everything, relying on architectural defenses for secret protection:

```bash
SSH_GUARD_MODE=safe guard server start --socket /tmp/guard.sock &

# Allowed: reading files (secrets in output are redacted)
guard run cat /etc/hosts
# 127.0.0.1 localhost

guard run cat /app/.env
# DB_HOST=localhost
# DB_PASSWORD=[REDACTED]
# API_TOKEN=[REDACTED]

# Still denied: privilege escalation
guard run sudo su
# DENIED: Escalation to root shell
```

### Paranoid mode for untrusted agents

Paranoid mode locks down to basic read-only inspection:

```bash
SSH_GUARD_MODE=paranoid guard server start --socket /tmp/guard.sock &

# Allowed: basic system state
guard run id
# uid=1000(agent) gid=1000(agent) groups=1000(agent)

guard run df -h
# Filesystem      Size  Used Avail Use% Mounted on
# /dev/sda1       100G   45G   55G  45% /

# Denied: file reading
guard run cat /etc/passwd
# DENIED: File reading blocked in paranoid mode

# Denied: environment inspection
guard run env
# DENIED: Environment variable dump blocked in paranoid mode
```

### Static deny policy

For fast-reject of known-bad patterns without an LLM call, add a static deny policy:

```bash
guard server start --policy examples/deny-policy.yaml --socket /tmp/guard.sock &
```

Static patterns are checked first. If a command matches a deny pattern, it is rejected immediately without an LLM call. Commands that pass static policy are then evaluated by the LLM.

See [`examples/deny-policy.yaml`](examples/deny-policy.yaml) for a reference policy with documented limitations of static glob matching.

### Custom system prompt

Replace the built-in prompt entirely for a specific deployment:

```bash
guard server start --system-prompt /etc/guard/my-prompt.txt --socket /tmp/guard.sock &
```

Or place a prompt file at `~/.config/guard/system-prompt.txt` to override automatically.

### Additive prompt

Append environment-specific instructions to the built-in prompt without replacing it:

```bash
# Via CLI flag
guard server start --system-prompt-append /etc/guard/extra-rules.txt &

# Or via environment variable
SSH_GUARD_PROMPT_APPEND=/etc/guard/extra-rules.txt guard server start &
```

Example additive prompt (`extra-rules.txt`):

```
Additional rules for this environment:

- This server runs a PostgreSQL database. Allow SELECT queries via psql but deny DROP, DELETE, or TRUNCATE.
- The /opt/app directory contains the application. Allow reads but deny writes.
- Allow docker ps and docker logs but deny docker exec, docker run, and docker rm.
```

The additive prompt is appended to whichever base prompt is active (default, safe, paranoid, or custom), letting operators customize behavior without maintaining a full prompt fork.

## Agent integration

Point your agent's command execution at `guard run` instead of direct execution.

### MCP server

Guard can run as a stdio MCP server so agents call a tool instead of shelling out:

```bash
guard config set-server ~/.guard/guard.sock
guard mcp serve
```

The server exposes a `guard_run` tool:

```json
{
  "binary": "ps",
  "args": ["aux"]
}
```

Response:

```json
{
  "allowed": true,
  "reason": "Read-only process listing",
  "exit_code": 0,
  "stdout": "USER  PID ...",
  "stderr": null
}
```

Denied commands return `isError: true` with the denial reason, so the agent can revise the command.

<details>
<summary><b>Claude Code (CLAUDE.md)</b></summary>

```markdown
# Command Execution

Use the guard MCP server for all command execution.
Never use interactive sessions.
```

</details>

<details>
<summary><b>OpenHands / SWE-Agent</b></summary>

```bash
export SSH_GUARD_LLM_API_KEY="..."
export SSH_GUARD_MODE=default
alias ssh=guard
```

</details>

<details>
<summary><b>LangChain / CrewAI tool definition</b></summary>

```python
import subprocess

def guarded_command(command: str, args: list[str]) -> str:
    """Execute a command through the guard."""
    result = subprocess.run(
        ["guard", "run", command] + args,
        capture_output=True, text=True, timeout=60,
    )
    if result.returncode != 0:
        return f"DENIED: {result.stderr.strip()}"
    return result.stdout
```

</details>

## Security model

Guard provides defense in depth through three layers:

1. **Environment isolation** (`env_clear`): Child processes inherit only safe environment variables (`PATH`, `HOME`, `USER`, `LANG`, `TERM`, etc.). API keys and secrets are not accessible to executed commands.

2. **Output redaction**: Known secret values (API keys, auth tokens, tool secrets) are exact-match redacted from stdout/stderr before returning to the agent. Regex patterns catch `*_TOKEN`, `*_KEY`, `*_SECRET`, `*_PASSWORD`, PEM blocks, and JWTs.

3. **LLM evaluation**: Each command is analyzed for destructive intent, privilege escalation, reverse shells, obfuscated payloads, tool side-channel abuse, and prompt injection. The LLM evaluates the full command including all chained parts.

## Audit logging

Guard logs all decisions via `tracing`. Configure log level with `RUST_LOG`:

```bash
RUST_LOG=info guard server start    # decisions + token usage
RUST_LOG=debug guard server start   # verbose request/response logging
```

LLM token usage is logged per evaluation:

```
[LLM_USAGE] model=openai/gpt-5.4-nano attempt=1 prompt_tokens=3594 completion_tokens=47 total_tokens=3641 status=ok
```

## Limitations

- **Not a sandbox.** Guard is a policy gate, not an isolation boundary. Defense-in-depth (seccomp, read-only FS, restricted users, network segmentation) is still needed for adversarial environments.
- **No interactive sessions.** Agents get command execution only.
- **LLM latency.** Each command adds ~0.5-2s for the LLM call.
- **Fail-closed.** If the LLM call fails or returns unparseable output, the command is denied.

## License

MIT
