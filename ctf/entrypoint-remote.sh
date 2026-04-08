#!/bin/bash
set -e

# Generate host keys if missing
ssh-keygen -A

# If an authorized key was mounted, install it
if [ -f /tmp/agent_key.pub ]; then
    cp /tmp/agent_key.pub /home/agent/.ssh/authorized_keys
    chown agent:agent /home/agent/.ssh/authorized_keys
    chmod 600 /home/agent/.ssh/authorized_keys
fi

# Start nginx in background
nginx &

# Start sshd in foreground
exec /usr/sbin/sshd -D -e
