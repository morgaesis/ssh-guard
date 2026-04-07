# Architecture

Source of truth hierarchy:

1. `src/server.rs` defines the privileged guard daemon, request protocol, policy evaluation, and command execution path.
2. `src/main.rs` defines operator-facing CLI entrypoints and how client configuration is resolved.
3. `src/mcp.rs` defines the stdio MCP facade that exposes the existing guard daemon as a tool for agent clients.

Current shape:

- `ssh-guard server start` runs the long-lived daemon over a UNIX socket or localhost TCP port.
- `ssh-guard <target> <command>` and `ssh-guard server connect ...` are thin clients over that daemon protocol.
- `ssh-guard mcp serve` is another thin client surface. It does not execute commands directly. It forwards MCP tool calls into the same daemon client path so policy, redaction, secrets, and SSH execution stay centralized.

Design constraints:

- Guard policy and command execution should exist in one place. New agent integrations should wrap the existing daemon rather than reimplement approval logic.
- MCP transport is stdio only in this repository. Network MCP transport would add a second auth and lifecycle surface and should be introduced only with a clear deployment requirement.
- Tool responses should preserve both raw command output and structured fields so clients can use either text-only or schema-aware handling.
