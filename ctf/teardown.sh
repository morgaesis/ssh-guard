#!/bin/bash
# Tear down the CTF sandbox. Stops each container explicitly before removing
# it so we don't leave zombie conmon/rootless processes behind, then removes
# the network.
set -u

CONTAINERS=(guard-local guard-remote guard-agent)

for c in "${CONTAINERS[@]}"; do
    # `podman stop` is a no-op if the container is already stopped or gone.
    podman stop --time 5 "$c" >/dev/null 2>&1 || true
done

for c in "${CONTAINERS[@]}"; do
    podman rm --force "$c" >/dev/null 2>&1 || true
done

podman network rm guard-net >/dev/null 2>&1 || true

# Report remaining ctf containers (should be none).
remaining=$(podman ps -a --filter 'name=^guard-(local|remote|agent)$' --format '{{.Names}}' 2>/dev/null || true)
if [ -n "$remaining" ]; then
    echo "Warning: these containers still exist after teardown:" >&2
    echo "$remaining" >&2
    exit 1
fi

echo "CTF environment torn down."
