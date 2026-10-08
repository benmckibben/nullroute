# nullroute: The 15-Second Aha! Demo
# Generates a crisp terminal demo showing zero-leak isolation in action.
# Compatible with VHS (https://github.com/charmbracelet/vhs)

Output demo.gif
Output demo.mp4

Set FontSize 18
Set Width 900
Set Height 520
Set Padding 20
Set Theme "Catppuccin Mocha"
Set FontFamily "JetBrains Mono"
Set TypingSpeed 40ms

# Scene 1: The Leaky Test
Type "python3 examples/01-python-test-leak/test_payment.py"
Enter
Sleep 2.5s

# Scene 2: The Instant Seal
Type "nullroute run -- python3 examples/01-python-test-leak/test_payment.py"
Enter
Sleep 3s

# Scene 3: Surgical Bridge with --allow
Type "nullroute run --allow example.com -- python3 examples/01-python-test-leak/test_payment.py"
Enter
Sleep 3.5s

# Scene 4: Summary & Inspect
Type "nullroute run --allow example.com --port 5432 --inspect --dry-run -- true"
Enter
Sleep 4s
