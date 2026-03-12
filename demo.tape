# VHS tape file for ssh-guard demo recording
# Run: vhs demo.tape

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

Type "# Read-only mode (default) - safe commands pass silently"
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

Type "# sudo is evaluated by the underlying command, not blanket-denied"
Enter
Sleep 500ms
Type "ssh-guard server 'sudo cat /var/log/syslog'"
Enter
Sleep 3s

Type "ssh-guard server 'sudo rm -rf /'"
Enter
Sleep 3s

Type "# Interactive sessions are blocked"
Enter
Sleep 500ms
Type "ssh-guard server"
Enter
Sleep 2s

Type "# Output is automatically redacted for secrets"
Enter
Sleep 500ms
Type "ssh-guard server 'cat .env'"
Enter
Sleep 3s
