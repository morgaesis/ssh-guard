# Deployment

This document covers long-running `ssh-guard` server deployment.

## Scope

Use this when `ssh-guard` should listen on a local UNIX socket and serve local clients through a system service.

## Files

Example systemd files are included here:

- [`deployment/systemd/ssh-guard.service`](deployment/systemd/ssh-guard.service)
- [`deployment/systemd/ssh-guard.env.example`](deployment/systemd/ssh-guard.env.example)

These examples are intentionally generic. Adjust user, group, socket path, allowed UIDs, mode, and hardening directives for the target host.

## Suggested Layout

- Binary: `/usr/local/bin/ssh-guard`
- Service unit: `/etc/systemd/system/ssh-guard.service`
- Environment file: `/etc/default/ssh-guard`
- UNIX socket: `/run/ssh-guard/ssh-guard.sock`

## Example Flow

Install the binary:

```bash
install -m 0755 ssh-guard /usr/local/bin/ssh-guard
```

Install the environment file:

```bash
install -m 0600 deployment/systemd/ssh-guard.env.example /etc/default/ssh-guard
```

Install the unit:

```bash
install -m 0644 deployment/systemd/ssh-guard.service /etc/systemd/system/ssh-guard.service
```

Reload and start:

```bash
systemctl daemon-reload
systemctl enable --now ssh-guard
```

Verify:

```bash
systemctl status ssh-guard
ls -l /run/ssh-guard/ssh-guard.sock
```

## Notes

- The service examples assume server mode over a UNIX socket.
- The socket can be world-connectable at the filesystem layer because authorization is enforced by peer UID in the server.
- Restrict access with `--users` to the client UIDs that should be able to submit requests.
- For LLM-backed evaluation, provide credentials through the environment file rather than command-line arguments.
- For static-policy-only deployments, use `--llm=false` or `--no-llm` and provide `SSH_GUARD_MODE` or a policy file.
