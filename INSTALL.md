# Install

Guard is a single binary with no runtime dependencies beyond an LLM API key.

## Options

Install from source:

```bash
cargo install --path .
```

Build locally without installing:

```bash
cargo build --quiet --release
./target/release/guard --version
```

Install from a GitHub release artifact:

```bash
# Example for Linux x86_64
curl -fsSLO https://github.com/morgaesis/guard/releases/download/v0.1.0/guard-v0.1.0-x86_64-unknown-linux-gnu.tar.gz
tar -xzf guard-v0.1.0-x86_64-unknown-linux-gnu.tar.gz
install -m 0755 guard ~/.local/bin/guard
```

Choose the release asset that matches the target platform:

- `x86_64-unknown-linux-gnu`
- `aarch64-unknown-linux-gnu`
- `x86_64-apple-darwin`
- `aarch64-apple-darwin`

## Basic setup

Set an API key before use:

```bash
export SSH_GUARD_LLM_API_KEY="..."
```

Or:

```bash
export OPENROUTER_API_KEY="..."
```

Verify the binary:

```bash
guard --version
guard server start &
guard run uptime
```

## Configuration

Configuration is environment-driven. See [`.env.example`](.env.example) for all available variables.

Key variables:

- `SSH_GUARD_LLM_API_KEY` / `OPENROUTER_API_KEY` -- LLM API key (required)
- `SSH_GUARD_API_URL` -- LLM endpoint (default: OpenRouter)
- `SSH_GUARD_MODEL` -- Model (default: `google/gemini-3-flash-preview`)
- `SSH_GUARD_MODE` -- Evaluation mode (default: `default`)
- `SSH_GUARD_TIMEOUT` -- LLM call timeout in seconds (default: `10`)

For long-running service deployment, see [DEPLOYMENT.md](DEPLOYMENT.md).
