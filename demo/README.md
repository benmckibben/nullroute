# demo

Assets for the terminal demo (the "15-second aha").

| File | What it is |
|---|---|
| `run-demo.sh` | Plays the demo live in your terminal (also fine for asciinema). Finds `target/debug`, `target/release` or a `nullroute` on PATH. |
| `nullroute-demo.tape` | [VHS](https://github.com/charmbracelet/vhs) script that records the same story to `demo/demo.gif` and `demo/demo.mp4`. |
| `test_leak.py` | The accidental external call used by the tape. |

## Rendering the tape

Run VHS from the **repository root** (the `Output` paths in the tape are relative
to the directory VHS is started in):

```bash
cargo build                      # or: cargo install --path .
vhs demo/nullroute-demo.tape     # writes demo/demo.gif and demo/demo.mp4
```

VHS needs `ttyd` and `ffmpeg` on PATH (see the VHS README), and the tape needs
`python3` and access to example.com. A hidden preamble in the tape `cd`s into
`demo/` and puts `target/debug` and `target/release` on PATH before recording
starts, so neither the `cd` nor the PATH setup shows up in the GIF. `demo.gif` is
committed (the README embeds it), so re-rendering changes a tracked file: re-render
and commit it deliberately, not as a side effect of unrelated work. `demo.mp4` is
git-ignored and not committed. Neither is part of the published crate.
