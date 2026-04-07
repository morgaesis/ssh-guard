# Install

`ssh-guard` is a single binary. There is no installer script in this repository.

## Options

Install from source:

```bash
cargo install --path .
```

Build locally without installing:

```bash
cargo build --release
./target/release/ssh-guard --version
```

Install from a GitHub release artifact:

```bash
# Example for Linux x86_64
curl -fsSLO https://github.com/morgaesis/ssh-guard/releases/download/v0.0.3/ssh-guard-v0.0.3-x86_64-unknown-linux-gnu.tar.gz
tar -xzf ssh-guard-v0.0.3-x86_64-unknown-linux-gnu.tar.gz
install -m 0755 ssh-guard ~/.local/bin/ssh-guard
```

Choose the release asset that matches the target platform:

- `x86_64-unknown-linux-gnu`
- `aarch64-unknown-linux-gnu`
- `x86_64-apple-darwin`
- `aarch64-apple-darwin`

## Basic Setup

Set an API key before use:

```bash
export SSH_GUARD_API_KEY="..."
```

Or:

```bash
export OPENROUTER_API_KEY="..."
```

Verify the binary:

```bash
ssh-guard --version
ssh-guard myserver 'uptime'
```

## Configuration

Configuration is environment-driven.

Common variables:

- `SSH_GUARD_API_KEY`
- `OPENROUTER_API_KEY`
- `SSH_GUARD_API_URL`
- `SSH_GUARD_MODEL`
- `SSH_GUARD_MODE`
- `SSH_GUARD_REDACT`
- `SSH_GUARD_TIMEOUT`

For long-running service deployment, systemd examples are in [DEPLOYMENT.md](DEPLOYMENT.md) and [`deployment/systemd/ssh-guard.service`](deployment/systemd/ssh-guard.service).
