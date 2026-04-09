#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
NETWORK="guard-net"
BINARY="$PROJECT_DIR/target/release/guard"

# Require API key
if [ -z "${SSH_GUARD_LLM_API_KEY:-${SSH_GUARD_API_KEY:-}}" ] && [ -z "${OPENROUTER_API_KEY:-}" ]; then
    echo "Error: Set SSH_GUARD_LLM_API_KEY or OPENROUTER_API_KEY"
    exit 1
fi
API_KEY="${SSH_GUARD_LLM_API_KEY:-${SSH_GUARD_API_KEY:-${OPENROUTER_API_KEY:-}}}"

# Resolve external DNS for container use
OPENROUTER_IP=$(dig +short openrouter.ai A | head -1)
if [ -z "$OPENROUTER_IP" ]; then
    echo "Error: Could not resolve openrouter.ai"
    exit 1
fi

echo "=== Guard CTF Setup ==="

# Check binary exists
if [ ! -f "$BINARY" ]; then
    echo "Building guard binary..."
    (cd "$PROJECT_DIR" && cargo build --quiet --release)
fi

# Create network
podman network exists "$NETWORK" 2>/dev/null || podman network create "$NETWORK"
echo "Network: $NETWORK"

# Clean up old containers
podman rm -f guard-local guard-remote guard-agent 2>/dev/null || true

# Generate SSH key for agent (shared between containers)
KEYDIR="$SCRIPT_DIR/.keys"
mkdir -p "$KEYDIR"
if [ ! -f "$KEYDIR/agent_key" ]; then
    ssh-keygen -t ed25519 -f "$KEYDIR/agent_key" -N "" -C "agent@ctf" -q
    echo "Generated SSH keypair"
fi

# Copy binary to build context
cp "$BINARY" "$SCRIPT_DIR/guard"

# Build containers
echo "Building guard-remote..."
podman build -t guard-remote -f "$SCRIPT_DIR/Containerfile.remote" "$SCRIPT_DIR"

echo "Building guard-local (shell mode)..."
podman build -t guard-local -f "$SCRIPT_DIR/Containerfile.local" "$SCRIPT_DIR"

echo "Building guard-agent (MCP-only mode)..."
podman build -t guard-agent -f "$SCRIPT_DIR/Containerfile.agent" "$SCRIPT_DIR"

rm -f "$SCRIPT_DIR/guard"

# Start remote
echo "Starting guard-remote..."
podman run -d \
    --name guard-remote \
    --network "$NETWORK" \
    --hostname guard-remote \
    -v "$KEYDIR/agent_key.pub:/tmp/agent_key.pub:ro" \
    guard-remote

sleep 2

# Start local (shell mode -- for manual testing)
echo "Starting guard-local..."
podman run -d \
    --name guard-local \
    --network "$NETWORK" \
    --hostname guard-local \
    --add-host openrouter.ai:$OPENROUTER_IP \
    -e "SSH_GUARD_LLM_API_KEY=$API_KEY" \
    -v "$KEYDIR/agent_key:/home/agent/.ssh/id_ed25519:ro" \
    -v "$KEYDIR/agent_key.pub:/home/agent/.ssh/id_ed25519.pub:ro" \
    guard-local

sleep 3

echo ""
echo "=== Containers Running ==="
podman ps --filter name=guard --format "table {{.Names}}\t{{.Status}}"

echo ""
echo "=== Usage ==="
echo "Shell mode:    podman exec -it guard-local bash"
echo "MCP-only CTF:  podman run -i --rm --name guard-agent --network $NETWORK --hostname guard-agent \\"
echo "                 --add-host openrouter.ai:$OPENROUTER_IP \\"
echo "                 -e SSH_GUARD_LLM_API_KEY=\$SSH_GUARD_LLM_API_KEY \\"
echo "                 -v $KEYDIR/agent_key:/home/agent/.ssh/id_ed25519:ro \\"
echo "                 guard-agent"
echo "View logs:     podman logs guard-local"
echo "Tear down:     $SCRIPT_DIR/teardown.sh"
