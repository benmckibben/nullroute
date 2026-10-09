# Design notes

Short write-ups of design questions that are bigger than one pull request. Each note says what the
code does today, what I measured, the options, a recommendation and a plan. They are **proposals**:
nothing in them is implemented unless a note says so, and the README stays the description of what
the released behaviour is.

| Note | Question | Recommendation in one line |
|---|---|---|
| [running-as-root.md](running-as-root.md) | What should happen when nullroute is started as uid 0 (the command keeps its capabilities and can unmount the socket decoys), and what about file descriptors inherited from outside? | Map a root caller to an unprivileged id inside the namespace (`65534 0 1`), no flag; mark inherited sockets close-on-exec with an opt-out, in a later PR. |
| [pid-namespace.md](pid-namespace.md) | How to close the last lifecycle gap (the command's own children survive a SIGKILL of nullroute) with a PID namespace; who is pid 1; what changes for `/proc`, signals and job control; why not cgroups. | Do it: a tiny init in nullroute's binary as pid 1, own `clone` + `exec` instead of `Command`, fresh `/proc`, phased behind a flag first. |
| [exit-codes.md](exit-codes.md) | What exit codes does nullroute produce, which are inconsistent (more than 64 `--port` → 125 while other argument errors are 2, and more), and what policy should replace them? | 2 = invalid invocation (decided from the arguments), 125 = sandbox could not be set up, 126/127 = command not executable / not found; fix >64 ports first. |

## Conventions

- Claims are tagged **[verified]** (I ran it, the command or setup is in the note),
  **[reasoned]** (from kernel semantics or the code, not run) or **[unverified]** (neither). Every
  note ends with what is unverified.
- Experiments that needed throwaway programs (small C or Python helpers) describe what the
  program did instead of committing it; none of them is part of the build.
- Sketched diffs are sketches against the tree they were written on. Re-check them before applying.
- Host used for the measurements: Linux 6.6 (WSL2) on x86_64 with unprivileged user namespaces
  enabled. Behaviour on other kernels and in containers is called out where it was or was not tried.
- These files are not part of the published crate (`Cargo.toml`'s `include` lists only sources, tests,
  the README, the changelog, the licences and the manifest), so links to them are for people reading the
  repository.

Add a note by copying the structure of an existing one: summary and recommendation first, then the
evidence, the options, a plan and a test plan, then what is unverified. Keep this index in step.
