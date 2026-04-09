# Roadmap

## Completed

- LLM-only evaluation with descriptive prompts (no hard-coded static policies by default).
- Three evaluation modes: default, safe, paranoid with mode-specific compiled prompts.
- Environment isolation (`env_clear` + allowlist) preventing API key leakage to child processes.
- Exact-match and regex-based output redaction for secrets in command output.
- Additive prompt support (`--system-prompt-append`) for environment-specific customization.
- MCP stdio server (`guard mcp serve`) for agent tool integration.
- Token usage tracking and audit logging via `tracing`.
- Adversarial CTF validation across three frontier models (Claude Opus 4.6, Gemini 3 Flash, GPT 5.4).

## Next

- Add integration coverage for `mcp serve` against a live local guard daemon so MCP behavior is validated end to end.
- Consider Streamable HTTP MCP transport only after there is a concrete deployment need and an authentication model for it.
- Binary allowlist for the server (restrict which binaries can be executed, not just what arguments are passed).
- Seccomp/AppArmor profile generation for containerized deployments.
- If users need richer agent workflows, add more MCP tools only when they map cleanly onto existing guard capabilities instead of creating parallel policy paths.
