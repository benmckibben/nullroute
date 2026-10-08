# nullroute: The 15-Second Aha! Demo
Output demo.gif
Output demo.mp4

Set FontSize 16
Set Width 960
Set Height 580
Set Padding 18
Set Theme "Catppuccin Mocha"
Set FontFamily "JetBrains Mono"
Set TypingSpeed 35ms

# Scene 1: The Leaky Call
Type "python3 test_leak.py"
Enter
Sleep 2.5s

# Scene 2: Instant Seal
Type "nullroute run -- python3 test_leak.py"
Enter
Sleep 3s

# Scene 3: Surgical Bridge
Type "nullroute run --allow example.com -- python3 test_leak.py"
Enter
Sleep 3.5s

# Scene 4: Inspect Topology
Type "clear"
Enter
Sleep 0.5s
Type "nullroute run --allow example.com --port 5432 --inspect --dry-run -- true"
Enter
Sleep 4.5s
