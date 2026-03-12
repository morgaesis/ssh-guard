# ssh-guard Reference

Detailed configuration, architecture, and integration guide.

## How it works

```
Agent ──> ssh-guard ──> LLM (approve/deny?) ──> ssh ──> remote server
                                                  │
                                              redact output
                                                  │
                                              ◄── agent sees clean output
```

1. Agent calls `ssh-guard host 'command'` instead of `ssh`
2. ssh-guard extracts the remote command from SSH arguments
3. Command is sent to an LLM with the active mode's policy prompt
4. LLM returns a structured decision via function calling: `{decision, reason, risk}`
5. **APPROVE**: command runs silently, output optionally redacted
6. **DENY**: error message printed to stderr, exit code 1

## Mode details

### readonly (default)

Allows: `cat`, `ls`, `grep`, `find`, `head`, `tail`, `less`, `stat`, `wc`, `diff`, `md5sum`, `sha256sum`, `uptime`, `df`, `free`, `ps`, `top`, `who`, `id`, `hostname`, `uname`, `ip`, `ss`, `netstat`, `lsblk`, `mount`, `systemctl status`, `journalctl`, `docker ps`, `docker logs`, `docker inspect`, `kubectl get`, `kubectl describe`, `kubectl logs`, `dpkg -l`, `rpm -qa`, `apt list`, `pip list`, `snap list`, `printenv`, `env`, `locale`, `timedatectl status`

Denies: Any command that writes, modifies, installs, removes, restarts, creates, or deletes anything. Also denies shell interpreters (`bash -c`, `python -c`), output redirection (`>`, `>>`), tunneling, and raw privilege escalation (`su`, `doas`).

### paranoid

Like readonly but also denies reading file contents, environment variables, logs, database queries, network captures, and SSH/TLS material. Only structural metadata is allowed: file listings, process lists, disk usage, network topology.

Use this when the agent should be able to see *what exists* but not *what it contains*.

### safe

Allows normal operational work: reads, targeted writes, service restarts on specific services, package installs of named packages, container operations on named targets, git operations, text processing.

Denies: mass deletion, disk operations, broad chmod/chown, reboots, mass service disruption, unscoped package upgrades, destructive k8s operations, database drops, network lockout, unverified remote code execution, kernel modifications, security-sensitive user/auth changes.

## sudo handling

All modes evaluate the command *after* `sudo`, not the keyword itself. sudo flags (`-u`, `-E`, `-H`, `-i`, etc.) are stripped before evaluation.

| Command | readonly | paranoid | safe |
|---------|----------|----------|------|
| `sudo ls /etc/nginx/` | APPROVE | APPROVE | APPROVE |
| `sudo cat /var/log/syslog` | APPROVE | DENY | APPROVE |
| `sudo printenv` | APPROVE | DENY | APPROVE |
| `sudo systemctl restart nginx` | DENY | DENY | APPROVE |
| `sudo rm -rf /etc/nginx/` | DENY | DENY | DENY |
| `sudo reboot` | DENY | DENY | DENY |

## Risk scoring

The LLM assigns a risk score (0-10) to every command:

| Score | Meaning | Examples |
|-------|---------|----------|
| 0-1 | Harmless read | `uptime`, `hostname`, `whoami` |
| 2-3 | Safe read with some info exposure | `cat /etc/hosts`, `ps aux` |
| 4-5 | Moderate: reads sensitive data or minor writes | `cat /etc/passwd`, `touch /tmp/test` |
| 6-7 | Significant: service changes, package installs | `systemctl restart app`, `apt install pkg` |
| 8-9 | Dangerous: broad writes, destructive operations | `rm -rf /var/data/`, `kubectl delete deployment` |
| 10 | Catastrophic: system destruction, irreversible | `rm -rf /`, `dd if=/dev/zero of=/dev/sda` |

Risk is logged but does not affect the approve/deny decision (that's the mode's job). It's useful for audit and alerting.

## Output redaction patterns

When `SSH_GUARD_REDACT=true`, these patterns are filtered from stdout:

| Pattern | Example match | Replacement |
|---------|--------------|-------------|
| `*_TOKEN=...`, `*_KEY=...`, `*_SECRET=...`, `*_PASSWORD=...`, `*_CREDENTIAL=...`, `*_AUTH=...` | `API_KEY=abc123` | `API_KEY=[REDACTED]` |
| `password=...`, `secret=...`, `token=...`, `bearer=...` | `password: hunter2` | `password: [REDACTED]` |
| PEM private key blocks | `-----BEGIN RSA PRIVATE KEY-----` | `-----BEGIN RSA PRIVATE KEY----- [REDACTED]` |
| `sk-*` prefixed strings (20+ chars) | `sk-abc123def456...` | `[REDACTED]` |
| JWT tokens (`eyJ...`) | `eyJhbGciOi...` | `[REDACTED]` |

Redaction is best-effort, not a security boundary. It catches common patterns but a determined agent could construct commands to exfiltrate data through side channels. Pair with `paranoid` mode for stronger guarantees.

## .env file resolution

ssh-guard walks from `$PWD` to `/` collecting `.env` files, then sources them in reverse order (root first, closest last). This means:

```
/home/user/project/.env     <- wins (sourced last)
/home/user/.env              <- provides defaults
/home/.env                   <- if it exists
```

Variables set in the environment before invocation take precedence over all `.env` files.

## Function calling

ssh-guard uses native LLM function calling (not freeform JSON parsing) for reliable structured responses.

Tool schema sent to the LLM:

```json
{
  "name": "ssh_command_decision",
  "parameters": {
    "type": "object",
    "properties": {
      "decision": {"type": "string", "enum": ["APPROVE", "DENY"]},
      "reason": {"type": "string"},
      "risk": {"type": "integer", "minimum": 0, "maximum": 10}
    },
    "required": ["decision", "reason", "risk"]
  }
}
```

The model is forced to call this function via `tool_choice`. A freeform JSON fallback exists for models that don't support function calling.

## Custom prompts

Override any mode with a custom prompt:

```bash
export SSH_GUARD_PROMPT='You are a database-team SSH filter.
APPROVE: any psql, pg_dump, or pg_restore command.
DENY: everything else.
Respond as JSON: {"decision": "APPROVE"|"DENY", "reason": "...", "risk": 0-10}'
```

## FAQ

**Q: How do I stop my AI agent from running dangerous SSH commands?**
A: Replace `ssh` with `ssh-guard` in the agent's config. Set `SSH_GUARD_API_KEY` and optionally `SSH_GUARD_MODE`. The agent's commands will be evaluated by an LLM before execution.

**Q: How do I prevent AI agents from leaking secrets over SSH?**
A: Use `SSH_GUARD_MODE=paranoid` and `SSH_GUARD_REDACT=true`. Paranoid mode blocks reading file contents and env vars. Redaction filters catch secrets in approved command output.

**Q: How do I give my AI agent safe SSH access to production?**
A: Use ssh-guard with `SSH_GUARD_MODE=readonly` for investigation tasks, or `SSH_GUARD_MODE=safe` for ops tasks. Always pair with a restricted SSH user and network segmentation.

**Q: Does this work with LangChain / CrewAI / AutoGen / OpenHands?**
A: Yes. ssh-guard is a CLI binary. Any agent framework that can call `subprocess.run(["ssh-guard", host, cmd])` works. See the main README for integration examples.

**Q: What LLM providers are supported?**
A: Any OpenAI-compatible API (OpenRouter, OpenAI, Together, Groq, Ollama, vLLM, etc.) and the Anthropic API natively. Default is OpenRouter with Gemini Flash.

**Q: What if the LLM is wrong?**
A: ssh-guard is fail-closed: unparseable responses and API failures result in denial. For false denials, add the command's base name to `SSH_GUARD_PASSTHROUGH`. For false approvals, tighten the mode or provide a custom prompt. The LLM is a heuristic gate, not a formal verifier.
