# VHS tape file for ssh-guard demo recording
# Run: vhs demo.tape
# Requires: ssh-guard binary in PATH, a reachable SSH host, SSH_GUARD_API_KEY set

Output demo.gif
Set FontSize 14
Set Width 1000
Set Height 500
Set Theme "Catppuccin Mocha"
Set TypingSpeed 50ms
Set Padding 20

Type "# ssh-guard: LLM-powered SSH command filter for AI agents"
Enter
Sleep 1s

Type "# Safe commands pass silently"
Enter
Sleep 500ms
Type "ssh-guard server 'uptime'"
Enter
Sleep 3s

Type "# Dangerous commands get denied with a risk score"
Enter
Sleep 500ms
Type "ssh-guard server 'rm -rf /etc/nginx/'"
Enter
Sleep 3s

Type "# sudo is evaluated by the underlying command"
Enter
Sleep 500ms
Type "ssh-guard server 'sudo cat /var/log/syslog'"
Enter
Sleep 3s

Type "ssh-guard server 'sudo rm -rf /'"
Enter
Sleep 3s

Type "# Verbose mode shows the decision process"
Enter
Sleep 500ms
Type "ssh-guard -vv server 'ls -la /tmp'"
Enter
Sleep 4s

Type "# Interactive sessions are blocked"
Enter
Sleep 500ms
Type "ssh-guard server"
Enter
Sleep 2s
