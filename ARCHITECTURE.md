# Architecture

Source of truth hierarchy:

1. `src/server.rs` -- privileged guard daemon: request protocol, policy evaluation, command execution, environment isolation, and output redaction.
2. `src/evaluate.rs` -- LLM evaluator: prompt selection, OpenAI-compatible API calls, response parsing, token usage tracking.
3. `src/main.rs` -- operator-facing CLI: server start, client commands, shim management, MCP server, secret management.
4. `src/mcp.rs` -- stdio MCP facade: exposes `guard_run` tool for agent clients, backed by the daemon protocol.

## Execution flow

```
Agent -> guard run <cmd> -> Client -> Server -> Evaluator -> LLM API
                                                    |
                                              Static Policy (optional)
                                                    |
                                              Execute command
                                                    |
                                              env_clear + allowlist
                                                    |
                                              Output redaction
                                                    |
                                              Response to agent
```

## Security layers

1. **Environment isolation**: `cmd.env_clear()` strips all environment variables from child processes. Only safe variables are re-injected (`PATH`, `HOME`, `USER`, `LANG`, `TERM`, `TZ`, `SHELL`, `LOGNAME`, `XDG_RUNTIME_DIR`, `SSH_AUTH_SOCK`). API keys and secrets never reach executed commands.

2. **Output redaction**: Known secret values (API key, auth token, tool-injected secrets) are exact-match redacted from stdout/stderr. Regex patterns catch common secret formats (`*_TOKEN=`, `*_KEY=`, PEM blocks, JWTs, `sk-*` strings).

3. **LLM evaluation**: Commands are sent to an LLM with a mode-specific system prompt. The LLM analyzes intent, chained operations, obfuscation, tool side-channels, and prompt injection attempts. Returns `APPROVE`/`DENY` with risk score.

4. **Static policy** (optional, opt-in): Glob-pattern allow and deny lists for fast decisions on deterministically safe or unsafe commands. Allow matches skip the LLM; deny matches reject without an LLM call. Everything else falls through to the LLM evaluator. Disabled by default. Documented limitation: static patterns cannot parse shell operators, quoting, or semantics. See `examples/` for reference policies.

## Prompt architecture

System prompts live in `config/*.md` files and are compiled into the binary via `include_str!()`. Three prompts ship by default:

- `config/system-prompt.md` -- balanced default mode
- `config/system-prompt-safe.md` -- permissive safe mode
- `config/system-prompt-paranoid.md` -- restrictive paranoid mode

Override priority: `--system-prompt` flag > `~/.config/guard/system-prompt.txt` > mode-specific compiled prompt.

Additive prompts (`--system-prompt-append` or `SSH_GUARD_PROMPT_APPEND`) append text to whichever base prompt is active, letting operators customize behavior without maintaining a prompt fork.

The default evaluator is a single LLM call per command with bounded retries before failing closed. A multi-model fallback chain (`SSH_GUARD_LLM_MODELS`) is available as an opt-in for deployments that need to survive provider-specific outages; when unset, guard uses a single model with retries. See `examples/fallback-models.env`.

## Design constraints

- Policy evaluation and command execution exist in one place (the server). New agent integrations wrap the daemon rather than reimplementing approval logic.
- MCP transport is stdio only. Network MCP transport adds a second auth surface and should be introduced only with a clear deployment requirement.
- Tool responses preserve both raw command output and structured fields so clients can use either text-only or schema-aware handling.
- The guard binary name is `guard`. Environment variables retain the `SSH_GUARD_*` prefix for backwards compatibility.
