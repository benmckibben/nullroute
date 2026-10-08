# nullroute: The 15-Second Aha! Demo
#
# Render from the REPOSITORY ROOT:
#
#     cargo build            # or: cargo install --path .
#     vhs demo/nullroute-demo.tape
#
# - Output paths below are relative to the directory VHS is started in, so they
#   assume the repo root. demo/demo.gif and demo/demo.mp4 are git-ignored build
#   artifacts; do not commit them.
# - The hidden preamble (Hide ... Show) cd's into demo/ so the typed
#   `python3 test_leak.py` resolves, and puts ./target/debug and ./target/release
#   on PATH so the typed `nullroute` is the one built from this checkout (same
#   order as demo/run-demo.sh). A nullroute already on PATH, e.g. from
#   `cargo install --path .`, is the fallback. None of this is recorded.
# - Needs python3 and network access to example.com (scenes 1 and 3).
# - ttyd and ffmpeg must be installed as well, see https://github.com/charmbracelet/vhs

Require python3

Output demo/demo.gif
Output demo/demo.mp4

Set FontSize 16
Set Width 960
Set Height 580
Set Padding 18
Set Theme "Catppuccin Mocha"
Set FontFamily "JetBrains Mono"
Set TypingSpeed 35ms

# Hidden setup (not recorded): enter demo/ and put the built binary on PATH.
Hide
Type "cd demo"
Enter
Type 'export PATH="$PWD/../target/debug:$PWD/../target/release:$PATH"'
Enter
Type "clear"
Enter
Sleep 500ms
Show

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
