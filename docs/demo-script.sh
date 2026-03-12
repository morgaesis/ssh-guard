#!/usr/bin/env bash
# Scripted demo for asciinema recording.
# Simulates ssh-guard behavior without needing a real server or API key.
set -e

CYAN='\033[0;36m'
RED='\033[0;31m'
DIM='\033[2m'
RESET='\033[0m'

_type() {
  local text="$1"
  for ((i = 0; i < ${#text}; i++)); do
    printf '%s' "${text:$i:1}"
    sleep 0.04
  done
}

_prompt() {
  printf '%b$ %b' "$DIM" "$RESET"
}

_run() {
  _prompt
  _type "$1"
  sleep 0.3
  echo
}

_comment() {
  printf '%b# %s%b\n' "$CYAN" "$1" "$RESET"
  sleep 0.5
}

_denied() {
  printf '%bssh-guard: %s%b\n' "$RED" "$1" "$RESET"
}

_dim() {
  printf '%b%s%b\n' "$DIM" "$1" "$RESET"
}

echo
_comment "ssh-guard: LLM-powered SSH command filter for AI agents"
_comment "Default mode: readonly"
echo
sleep 0.5

_run "ssh-guard prod-db 'uptime'"
sleep 0.3
echo " 14:22:01 up 47 days,  3:15,  2 users,  load average: 0.42, 0.38, 0.35"
sleep 1

echo
_run "ssh-guard prod-db 'df -h /'"
sleep 0.3
echo "Filesystem      Size  Used Avail Use% Mounted on"
echo "/dev/sda1       100G   42G   58G  42% /"
sleep 1

echo
_comment "Dangerous commands are denied with risk score"
_run "ssh-guard prod-db 'rm -rf /var/lib/postgresql/'"
sleep 0.3
_denied "DENIED (risk=10) - Recursive deletion of database data directory."
sleep 1.5

echo
_comment "sudo is evaluated by the underlying command"
_run "ssh-guard prod-db 'sudo cat /var/log/postgresql/postgresql-15-main.log | tail -5'"
sleep 0.3
echo "2025-03-12 14:20:01.234 UTC [1234] LOG:  checkpoint complete"
echo "2025-03-12 14:21:15.567 UTC [1235] LOG:  connection received: host=10.0.1.5"
echo "2025-03-12 14:21:15.570 UTC [1235] LOG:  connection authorized: user=app"
echo "2025-03-12 14:22:00.891 UTC [1234] LOG:  checkpoint starting: time"
echo "2025-03-12 14:22:01.123 UTC [1234] LOG:  checkpoint complete"
sleep 1

echo
_run "ssh-guard prod-db 'sudo systemctl restart postgresql'"
sleep 0.3
_denied "DENIED (risk=7) - Modifies service state by restarting the database."
sleep 1.5

echo
_comment "Secrets are redacted from output"
_run "ssh-guard prod-db 'grep -i password /etc/app/config.yaml'"
sleep 0.3
echo "database_password: [REDACTED]"
echo "redis_auth_token: [REDACTED]"
sleep 1

echo
_comment "Interactive sessions are blocked"
_run "ssh-guard prod-db"
sleep 0.3
_denied "interactive sessions are not permitted through ssh-guard."
_denied "provide a command: ssh-guard prod-db 'command'"
_denied "for interactive access, use ssh directly."
sleep 1.5

echo
_comment "Switch modes for different policies"
_run "SSH_GUARD_MODE=safe ssh-guard prod-db 'systemctl restart myapp'"
sleep 0.3
echo ""
_dim "(service restarted)"
sleep 1

echo
