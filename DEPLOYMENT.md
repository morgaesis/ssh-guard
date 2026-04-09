# Deployment

Long-running `guard` server deployment as a system service.

## Scope

Use this when `guard` should listen on a local UNIX socket and serve local clients (AI agents, shims) through a system service.

## Recommended deployment

For production environments where AI agents operate:

- Run guard as a dedicated unprivileged user (e.g., `guard`).
- The agent process should run as a separate unprivileged user, restricted to connecting to the guard socket.
- Use `--users` to restrict which UIDs can submit requests.
- Provide the LLM API key via the environment file (`/etc/default/guard`), not CLI arguments.
- Enable systemd hardening directives (`NoNewPrivileges`, `ProtectSystem`, `PrivateTmp`).
- The agent should not have access to the guard process's `/proc/*/environ` or `/proc/*/cmdline` (ensured by running as a different user with standard procfs hidepid or systemd's `ProtectProc`).
- For containers, use `env_clear` (enabled by default) so child processes never see the API key. Output redaction (also default) catches secrets in command output.

## Files

Example systemd files:

- [`deployment/systemd/guard.service`](deployment/systemd/guard.service)
- [`deployment/systemd/guard.env.example`](deployment/systemd/guard.env.example)

These examples are intentionally generic. Adjust user, group, socket path, allowed UIDs, mode, and hardening directives for the target host.

## Suggested layout

- Binary: `/usr/local/bin/guard`
- Service unit: `/etc/systemd/system/guard.service`
- Environment file: `/etc/default/guard`
- UNIX socket: `/run/guard/guard.sock`

## Example flow

Install the binary:

```bash
install -m 0755 guard /usr/local/bin/guard
```

Install the environment file:

```bash
install -m 0600 deployment/systemd/guard.env.example /etc/default/guard
# Edit /etc/default/guard and set SSH_GUARD_LLM_API_KEY
```

Install the unit:

```bash
install -m 0644 deployment/systemd/guard.service /etc/systemd/system/guard.service
```

Reload and start:

```bash
systemctl daemon-reload
systemctl enable --now guard
```

Verify:

```bash
systemctl status guard
ls -l /run/guard/guard.sock
```

## Notes

- The service runs in server mode over a UNIX socket.
- The socket can be world-connectable at the filesystem layer because authorization is enforced by peer UID in the server.
- Restrict access with `--users` to the client UIDs that should be able to submit requests.
- For LLM-backed evaluation, provide credentials through the environment file rather than command-line arguments.
- For static-policy-only deployments, use `--no-llm` and provide a `--policy` file.
- Audit logs are emitted via `tracing` to stderr (captured by systemd journal). Set `RUST_LOG=info` in the environment file for standard logging.
