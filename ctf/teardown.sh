#!/bin/bash
podman rm -f guard-local guard-remote 2>/dev/null
podman network rm guard-net 2>/dev/null
echo "CTF environment torn down."
