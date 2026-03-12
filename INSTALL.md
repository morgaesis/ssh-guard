# Installing ssh-guard

## Quick install (Linux/macOS)

```bash
curl -fsSL https://raw.githubusercontent.com/morgaesis/ssh-guard/main/install.sh | bash
```

This detects your OS and architecture, downloads the latest release binary, and installs it to `~/.local/bin/`.

To install a specific version:

```bash
SSH_GUARD_VERSION=v0.0.1 curl -fsSL https://raw.githubusercontent.com/morgaesis/ssh-guard/main/install.sh | bash
```

## From source

Requires Rust 1.70+.

```bash
git clone https://github.com/morgaesis/ssh-guard.git
cd ssh-guard
cargo install --path .
```

## Manual download

Grab a binary from [GitHub Releases](https://github.com/morgaesis/ssh-guard/releases), extract it, and put it somewhere in your PATH:

```bash
tar xzf ssh-guard-v0.0.1-x86_64-unknown-linux-gnu.tar.gz
mv ssh-guard ~/.local/bin/
chmod +x ~/.local/bin/ssh-guard
```

### Available architectures

| Platform | Target |
|----------|--------|
| Linux x86_64 | `x86_64-unknown-linux-gnu` |
| Linux ARM64 | `aarch64-unknown-linux-gnu` |
| macOS x86_64 | `x86_64-apple-darwin` |
| macOS ARM64 (Apple Silicon) | `aarch64-apple-darwin` |

## Post-install setup

### 1. Set your API key

ssh-guard needs an LLM API key. The default endpoint is OpenRouter (cheap, supports many models).

```bash
# In your shell profile or a .env file:
export SSH_GUARD_API_KEY="your-openrouter-api-key"
# Or if you already have OPENROUTER_API_KEY set, ssh-guard uses it automatically
```

<details>
<summary>Using a different LLM provider</summary>

**Anthropic API directly:**
```bash
export SSH_GUARD_API_KEY="your-anthropic-key"
export SSH_GUARD_API_URL="https://api.anthropic.com/v1/messages"
export SSH_GUARD_API_TYPE="anthropic"
export SSH_GUARD_MODEL="claude-haiku-4-5-20251001"
```

**OpenAI:**
```bash
export SSH_GUARD_API_KEY="your-openai-key"
export SSH_GUARD_API_URL="https://api.openai.com/v1/chat/completions"
export SSH_GUARD_MODEL="gpt-4o-mini"
```

**Local model (Ollama, vLLM, etc.):**
```bash
export SSH_GUARD_API_KEY="not-needed"
export SSH_GUARD_API_URL="http://localhost:11434/v1/chat/completions"
export SSH_GUARD_MODEL="llama3"
```

</details>

### 2. Verify it works

```bash
ssh-guard your-server 'uptime'
```

If the API key is set and the server is reachable, you should see the uptime output with no extra noise.

### 3. Configure for your agents

#### Option A: Alias ssh to ssh-guard

```bash
# In the agent's environment
alias ssh=ssh-guard
```

#### Option B: Set SSH_GUARD as the SSH command

Many tools let you configure the SSH binary:

```bash
# Git
export GIT_SSH_COMMAND=ssh-guard

# Ansible
export ANSIBLE_SSH_EXECUTABLE=ssh-guard

# rsync
rsync -e ssh-guard ...
```

#### Option C: Per-project .env

Create a `.env` file in your project directory:

```bash
SSH_GUARD_API_KEY=your-key
SSH_GUARD_MODE=readonly
SSH_GUARD_LOG=/var/log/ssh-guard.log
```

ssh-guard walks up from the current directory looking for `.env` files, so this scopes config per project automatically.

## Updating

```bash
# Re-run the install script
curl -fsSL https://raw.githubusercontent.com/morgaesis/ssh-guard/main/install.sh | bash

# Or from source
cd ssh-guard && git pull && cargo install --path .
```

## Uninstalling

```bash
rm ~/.local/bin/ssh-guard
```
