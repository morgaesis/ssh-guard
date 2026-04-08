#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
NETWORK="guard-net"
BINARY="$PROJECT_DIR/target/release/ssh-guard"

# Require API key
if [ -z "${SSH_GUARD_API_KEY:-}" ] && [ -z "${OPENROUTER_API_KEY:-}" ]; then
    echo "Error: Set SSH_GUARD_API_KEY or OPENROUTER_API_KEY"
    exit 1
fi
API_KEY="${SSH_GUARD_API_KEY:-$OPENROUTER_API_KEY}"

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
podman rm -f guard-local guard-remote 2>/dev/null || true

# Generate SSH key for agent (shared between containers)
KEYDIR="$SCRIPT_DIR/.keys"
mkdir -p "$KEYDIR"
if [ ! -f "$KEYDIR/agent_key" ]; then
    ssh-keygen -t ed25519 -f "$KEYDIR/agent_key" -N "" -C "agent@ctf" -q
    echo "Generated SSH keypair"
fi

# Build remote container
echo "Building guard-remote..."
podman build -t guard-remote -f "$SCRIPT_DIR/Containerfile.remote" "$SCRIPT_DIR"

# Build local container (copy binary into context)
echo "Building guard-local..."
cp "$BINARY" "$SCRIPT_DIR/ssh-guard"
podman build -t guard-local -f "$SCRIPT_DIR/Containerfile.local" "$SCRIPT_DIR"
rm -f "$SCRIPT_DIR/ssh-guard"

# Start remote
echo "Starting guard-remote..."
podman run -d \
    --name guard-remote \
    --network "$NETWORK" \
    --hostname guard-remote \
    -v "$KEYDIR/agent_key.pub:/tmp/agent_key.pub:ro" \
    guard-remote

# Wait for sshd
sleep 2

# Start local
echo "Starting guard-local..."
podman run -d \
    --name guard-local \
    --network "$NETWORK" \
    --hostname guard-local \
    -e "SSH_GUARD_API_KEY=$API_KEY" \
    -e "SSH_GUARD_MODE=readonly" \
    -v "$KEYDIR/agent_key:/home/agent/.ssh/id_ed25519:ro" \
    -v "$KEYDIR/agent_key.pub:/home/agent/.ssh/id_ed25519.pub:ro" \
    guard-local

# Wait for guard daemon
sleep 3

echo ""
echo "=== Containers Running ==="
podman ps --filter name=guard --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"

echo ""
echo "=== Test connectivity ==="
podman exec guard-local ssh-guard run ssh -o StrictHostKeyChecking=no agent@guard-remote 'echo "Connection OK"' 2>&1 || echo "(test may fail due to LLM policy -- that's fine)"

echo ""
echo "=== Ready ==="
echo "Attach to local:  podman exec -it guard-local bash"
echo "Attach to remote:  podman exec -it guard-remote bash"
echo "View guard logs:   podman exec guard-local cat /home/agent/.guard/daemon.log"
echo "Tear down:         $SCRIPT_DIR/teardown.sh"
