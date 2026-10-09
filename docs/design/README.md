# Design notes

Write-ups of design questions that need more than a code change. Each note says what the code does,
what was measured, the options, a recommendation and a plan, and carries a **status**. A note with
status *open proposal* describes something that is not implemented, and the main README stays the
description of what nullroute does.

| Note | Status | Question | Outcome in one line |
|---|---|---|---|
| [running-as-root.md](running-as-root.md) | open proposal | What should happen when nullroute is started as uid 0 (the command keeps its capabilities and can unmount the socket decoys), and what about file descriptors inherited from outside? | Map a root caller to an unprivileged id inside the namespace (`65534 0 1`), no flag; mark inherited sockets close-on-exec with an opt-out. |
| [pid-namespace.md](pid-namespace.md) | open proposal | How to close the last lifecycle gap (the command's own children survive a SIGKILL of nullroute) with a PID namespace; who is pid 1; what changes for `/proc`, signals and job control; why not cgroups. | A tiny init in nullroute's binary as pid 1, own `clone` + `exec` instead of `Command`, fresh `/proc`, phased behind a flag first. |
| [exit-codes.md](exit-codes.md) | implemented, three items open | What exit codes does nullroute produce, and what policy do they follow? | 2 = invalid invocation (decided from the arguments), 125 = sandbox could not be set up, 126/127 = command not executable / not found. Open: `--dry-run` does not check the listener limit, "failed to run" wording, `--hide-socket` of a missing path. |

## Conventions

- Claims are tagged **[verified]** (run, with the command or setup in the note), **[reasoned]** (from
  kernel semantics or the code, not run) or **[unverified]** (neither). Notes end with what is unverified.
- Experiments that needed throwaway programs (small C or Python helpers) describe what the program did
  instead of committing it; none of them is part of the build.
- Sketched diffs are sketches against the tree they were written on. Re-check them before applying.
- Host used for the measurements: Linux 6.6 (WSL2) on x86_64 with unprivileged user namespaces
  enabled. Behaviour on other kernels and in containers is called out where it was or was not tried.
- These files are not part of the published crate (`Cargo.toml`'s `include` lists only sources, tests,
  the README, the changelog, the licences and the manifest), so links to them are for people reading the
  repository.

Add a note by copying the structure of an existing one: status and summary first, then the evidence,
the options, a plan and a test plan, then what is unverified. Keep this index in step, and when a
note's proposal is implemented, change its status and say what was done and what remains.
