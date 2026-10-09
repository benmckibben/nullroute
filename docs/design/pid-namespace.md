# A PID namespace for the command

Status: **open proposal** (not implemented). Scope: close the remaining lifecycle gap left by the
parent-death signal and the signal handling (the command dies with nullroute, but its own children can
survive) by running the command in its own PID namespace, and say what that changes for everything
around it.

Evidence tags: **[verified]** = run on the host under [Test host](#test-host);
**[reasoned]** = derived from kernel semantics, not run; **[unverified]** = neither.
Prototype code was throwaway (a ~70-line C program in a temp directory, deleted after use,
not committed); the core of it is described under [Prototype](#prototype).

## Summary

- The gap: if nullroute is SIGKILLed (OOM killer, a CI runner's hard kill), the kernel
  kills the *command* via `PR_SET_PDEATHSIG`, but the command's own children are orphaned,
  not killed, because the setting is not inherited across `fork`. **[verified]**: with
  `nullroute run -- sh -c 'sleep 4321 & sleep 4321 & wait'`, `kill -9` of nullroute left both
  `sleep` processes running.
- A PID namespace fixes it at the kernel level: when the namespace's init (pid 1) dies,
  the kernel SIGKILLs every process in the namespace. **[verified]**: same command under the
  prototype, `kill -9` of the launcher left no `sleep` processes.
- Recommendation: **yes, do it**, with a **tiny init in nullroute's own binary** as pid 1
  (it reaps, forwards `SIGTERM`/`SIGHUP`, and on command exit kills the rest and exits with
  the command's status), phased as: (1) refactor the spawn into our own `clone` + `exec` with
  no behaviour change, (2) add `CLONE_NEWPID` + a fresh `/proc` + the init, (3) make it the
  default with a `--no-pid-ns` escape hatch. cgroup v2 kill is not a substitute (below).
- Costs: a fresh `/proc` mount (so a mount namespace is always needed), the command sees
  only its own processes (that is also the benefit), `$PPID` is 1, pids are small and
  repeat across runs, and `getpgrp()`/`getsid()` read 0. All measured below.

## Test host

Linux 6.6.114.1-microsoft-standard-WSL2 (x86_64), util-linux 2.39.3, Python 3.12.3, gcc,
rustc 1.99, a local Docker daemon, unprivileged user (uid 1000, in the `docker` group).
Unprivileged user namespaces enabled (nullroute's own tests run here). cgroup v2 mounted
with `nsdelegate` and a systemd user manager (delegated cgroup subtree).

## What exists now

- `lifecycle::die_with_parent`: in the `pre_exec` hook, `prctl(PR_SET_PDEATHSIG, SIGKILL)`,
  then if `getppid() != parent` the child kills itself (the parent died before the prctl).
  Re-armed as the last setup step.
- `lifecycle::become_subreaper` + `kill_leftovers`: nullroute sets `PR_SET_CHILD_SUBREAPER`,
  so whatever the command orphans is reparented to nullroute; after the command exits,
  nullroute scans `/proc/self/task/*/children` and SIGKILLs and reaps them until none remain
  (5 s deadline). Needs `CONFIG_PROC_CHILDREN`.
- `signals.rs`: SIGINT/SIGQUIT ignored once the command runs (the terminal's group
  delivery reaches the command), SIGTERM/SIGHUP forwarded to the command's pid, all four
  blocked around spawn, and the child reads nullroute's `/proc/<ppid>/status`
  (opened early, read last) to replay a SIGINT/SIGQUIT that landed before the child existed.
- No PID namespace: the command sees the host's `/proc` and can `kill` the caller's other
  processes (**[verified]**: `kill -0` on an unrelated same-user process succeeds from inside).
  The README's "What nullroute is not" says so.
- The sandbox does nothing with `/proc` now: `run_hermetic` writes `/proc/self/{setgroups,uid_map,gid_map}`
  from the child, and `signals.rs` opens `/proc/<pid>/status`; nothing mounts it
  (**[verified]** by grepping `src/`: those and the `/proc/self/task` scan in `lifecycle.rs` are the only uses).

What survives a SIGKILL of nullroute now, for completeness: the command dies (PDEATHSIG),
its children live on (**[verified]** above), and a command that is itself a set-user-ID or
file-capability binary (e.g. `ping` with `cap_net_raw`) also lives on, because exec of such a
binary clears PDEATHSIG (**[reasoned]**; documented in `lifecycle.rs`; not run, `ping` here is
not file-capability based).

## Kernel behaviour measured

Prototype: a launcher that does `clone(CLONE_NEWUSER|CLONE_NEWNS|CLONE_NEWNET|CLONE_NEWPID|SIGCHLD)`;
the child is pid 1, writes the id maps, makes mounts private, optionally mounts a fresh
`/proc`, forks the command and reaps. All as an unprivileged user.

| Question | Result |
|---|---|
| `unshare(CLONE_NEWPID)` then `exec` (what `pre_exec` + std's exec would do): is the command in the new namespace? | **No** **[verified]**. The exec'd process keeps the old pid (102498) and `/proc/self/ns/pid` of the host; only its *children* enter the new one. Its first `fork` gets pid 1 in the new namespace; its second `fork` fails with `ENOMEM` ("Cannot allocate memory") once that pid-1 child has exited. So `Command` + `pre_exec` cannot do this alone. |
| `clone(CLONE_NEWPID)`: is the child pid 1? | Yes **[verified]**: `getpid()=1`, and `getppid()=0`, `getpgrp()=0`, `getsid()=0` (its parent, group and session leader are outside the namespace). |
| Does the existing `getppid() != parent` check in `die_with_parent` still work in pid 1? | **No** **[verified]**: `getppid()` is 0 there, so the check would always fire and kill the init at once. It must be replaced (see design). |
| Can pid 1 still write `/proc/self/uid_map` etc. through the host's `/proc`? | Yes **[verified]** (before any remount, "self" resolves in the parent's procfs). |
| Command's view without a `/proc` remount | Host `/proc`: `NSpid:\t<host pid> 3`; the host's processes are listed. |
| With a fresh `mount -t proc` (nosuid, nodev, noexec) | 5 numeric entries in `/proc`; `ps -e` lists exactly init, the shell and `ps` itself; the command is pid 2 with parent 1 **[verified]**. |
| `open(/proc/<nullroute host pid>/status)` after the remount | `ENOENT`, but an fd opened *before* the remount still reads that task's `SigPnd`/`ShdPnd` **[verified]**. `signals.rs` already opens it early for exactly this kind of reason, so the early-signal logic survives. |
| `kill -0 <host pid>` from inside | `No such process` **[verified]**. |
| `getpgrp()` / `getsid()` in the command | **0 and 0** **[verified]** (group/session leader is outside). |
| `tcgetpgrp(0)` on a pty | 0 (baseline: the real group id) **[verified]**. |
| Interactive `bash -i` on a pty under the namespace: background job, `jobs`, `fg`, Ctrl-C | All worked, same transcript shape as baseline **[verified]** (bash makes its own process group). |
| SIGTERM / SIGINT sent from outside to a pid 1 **without** a handler | Both ignored; the init stayed alive; only SIGKILL works **[verified]**. |
| Same with a SIGTERM/SIGHUP handler installed | Delivered, forwarded to the command; init exit status 143 **[verified]**. |
| Exit-status mapping when the init exits with the command's code | `exit 7` → 7; `kill -TERM $$` → 143; `kill -KILL $$` → 137 **[verified]**. |
| `kill -9` of the launcher (init has PDEATHSIG) | All processes in the namespace die: 0 survivors **[verified]**. Baseline now: 2 survivors **[verified]**. |
| Command exits while its background children run | The init's `kill(-1, SIGKILL)` + reap loop left 0 survivors **[verified]**. |
| `/proc/sys/kernel/ns_last_pid` (to start pids at a high number) | Writable for an id mapped to root; **not writable** for the identity mapping nullroute uses (`I/O error`) **[verified]**. |
| Fresh `/proc` inside a container with Docker's masked paths | Worked with `--security-opt seccomp=unconfined` (default seccomp blocks the `unshare` anyway) **[verified]**, so the "mount too revealing" kernel check did not trip there. Other container setups: **[unverified]**. |
| Cost | Prototype (clone + id maps + mounts + fresh `/proc` + exec `true`): about 2.5 ms per run over 200 runs. The current `nullroute run -q -- true` (debug build, everything else it does): about 4 ms. Not a controlled benchmark; the namespace part is small. |

## Design

### Who is pid 1

| Option | What | Verdict |
|---|---|---|
| **1. Tiny init in nullroute's binary (recommended)** | Between `clone` and `exec`, the child (pid 1) stays in a small loop; a second child (pid 2) execs the command | Reaps zombies, forwards signals, owns teardown. About 60 lines of allocation-free code. |
| 2. nullroute itself as pid 1 | Put the whole existing process in the namespace, command as child | **Rejected.** It would put the relay/proxy/DNS process in the *same user namespace* as the command. Currently the command cannot read `/proc/<nullroute>/ns/net` or ptrace nullroute because nullroute is in the parent user namespace (**[verified]**: the open is denied with `EACCES`). Sharing the namespace removes that barrier for the one process that holds the host network. |
| 3. Re-exec `/proc/self/exe __init` as pid 1 | Same as 1 but as a fresh exec'd image | Safer than 1 with respect to "Rust code after fork", costs an exec and a hidden subcommand plus passing the listener socketpair. Fall back to this if option 1's post-clone code turns out to need allocation. |
| 4. `unshare(NEWPID)` in `pre_exec` and let std exec | | **Impossible** (table: the exec'd process is not in the namespace). |

The init sits in the same user and network namespace as the command, so it must be treated
as part of the sandbox: it must hold no descriptor from the host side (close the listener
socketpair's child end after the handover; nothing else is inherited above fd 2 once the fd
sweep from [running-as-root.md](running-as-root.md) exists). It cannot be killed from inside
(signals from inside the namespace to pid 1 are ignored unless it has handlers, SIGKILL
included); a command that can ptrace it could only hurt itself.

### Process layout and the extra fork

```
P  nullroute (host pid namespace, host network; relays, proxy, DNS, report)
└─ I  init, pid 1   (clone CLONE_NEWUSER|NEWNET|NEWNS|NEWPID; same ns as the command)
   └─ C  the command, pid 2  (fork from I, then exec)
```

One more process than now, one more `fork` (I → C). Two ways to get there:

- **F2: replace `Command::spawn` with our own `clone` + `exec` (recommended).** The flags go
  straight into the raw `clone` syscall (`syscall(SYS_clone, flags|SIGCHLD, 0, 0, 0, 0)` is
  the same on x86_64 and aarch64 when the extra arguments are zero). P's child *is* the init,
  so P's `CHILD` pid for signal forwarding and `wait` stays the init's. Needs: argv/envp built
  before the clone (`Command`'s PATH search and env merging reimplemented, or use `execvpe`),
  an error pipe like std's (close-on-exec write end the command holds until exec; the init
  closes its copy right after forking the command, otherwise P would block on it), and the
  same `pre_exec` body moved into the child function. The "only raw syscalls, no allocation"
  rule still applies up to `exec`: nullroute is single-threaded at that point (`signals.rs` relies
  on it), so the heap is consistent, but the code should stay allocation-free anyway.
- F1: keep `Command` and fork inside `pre_exec`. Then std's exec happens in the *outer* child
  (not in the namespace), which becomes a shim that must wait for the init, relay signals and
  re-raise its status, and must close std's error pipe (otherwise P's `spawn` blocks until the
  shim exits, because the pipe's write end is inherited by the shim and the init). More
  moving parts than F2 for the same result. Not recommended.

### Setup order in the init (all raw syscalls)

1. `prctl(PR_SET_PDEATHSIG, SIGKILL)`; then check whether P is already gone. `getppid()` cannot
   be used (it is 0). Use a pipe created by P with the read end passed to the init (P keeps
   the write end; the init closes its own copy): a non-blocking read returning 0 means P has
   died, so kill the namespace and exit. (A `pidfd_open` of P and `pidfd_send_signal(fd, 0)`
   would also work on 5.3+ kernels.) The pipe also lets the init notice P's death later even if
   PDEATHSIG was cleared, e.g. by a credential change.
2. Write `setgroups`/`uid_map`/`gid_map` via `/proc/self/` (works as pid 1; table).
3. Make mounts private, bind decoys and masks (as now), then **mount a fresh `proc`** at `/proc`
   with `MS_NOSUID|MS_NODEV|MS_NOEXEC`. The mount namespace is then always needed: now it is
   created only when sockets are hidden or the sinkhole is on ("even a bare run usually gets one"
   already, because of the resolver masks, but not always).
4. `lo` up, listener handover, as now.
5. Fork C. In C: the existing tail of `pre_exec` unchanged (re-arm is not needed for C;
   `ChildMask::restore` replays an early SIGINT/SIGQUIT using the status fd opened before the
   remount; restore the signal mask), then `exec`.
6. In I: block nothing, install handlers for SIGTERM/SIGHUP that `kill(C, sig)`, leave SIGINT/SIGQUIT
   at default (ignored by pid 1; the terminal's group delivery reaches C directly, as now). Loop
   on `waitpid(-1)` (reaping every orphan reparented to pid 1). When C is reaped: `kill(-1, SIGKILL)`,
   reap until `ECHILD`, `_exit(code)` where code is the exit code or 128+signal.
   If the death pipe reports EOF: `kill(-1, SIGKILL)` and `_exit(137)`.

### Signals, exit status, early SIGINT, job control

- **Forwarding.** P's `forward` handler keeps `kill`ing its "child"; that is now I, which has
  a handler for TERM/HUP and relays to C (**[verified]** in the prototype). Delivery from
  an ancestor namespace to a pid 1 with a handler works; without a handler it would be silently
  dropped (**[verified]**), which is why C cannot be pid 1.
- **Exit status.** An init cannot re-raise a signal on itself (pid 1 ignores default-action
  signals), so it exits with `128 + N`. `run()` already computes `128 + sig` for signalled
  children and passes through `status.code()` otherwise, so the visible result is identical
  (**[verified]** 7, 143, 137). The only difference is "killed by signal" versus "exited with
  143" as seen by P, which nothing observes. If I itself is killed (OOM), P sees the signal and
  reports 128+N as now, and the kernel kills C.
- **Early SIGINT.** Unchanged: C does the `/proc/<P>/status` replay as its last step. The
  fd must be opened while the host `/proc` is still mounted, i.e. in I before step 3 or in P
  before the clone; `open_parent_status` already runs before the namespace changes, and the
  prototype confirmed an fd opened earlier still reads P's pending set after the remount.
  The existing test that lands a signal in the spawn window
  (`NULLROUTE_TEST_HOLD_BEFORE_SPAWN`) keeps working as long as the hold stays before the clone.
- **Ctrl-C / job control.** Ctrl-C goes to the foreground process group: P (ignores), I (pid 1
  ignores default-action signals from the terminal; **[verified]** for SIGINT from outside) and C
  (default action). Behaviour matches the current one. `bash -i` as the command still has job control
  **[verified]**. What changes: `getpgrp()`, `getsid()` and `tcgetpgrp()` report 0 for a command
  started from an interactive shell (group and session leader are outside the namespace).
  Programs that compare these ids to something they got elsewhere may misbehave
  (**[unverified]**; nothing tried did). `SIGTSTP` (Ctrl-Z) stops P and C as now; I ignores it (**[reasoned]**: pid 1 ignores default-action signals).
- **Subreaper.** With the namespace, orphans reparent to I, not P; `PR_SET_CHILD_SUBREAPER` and the
  `/proc/self/task/*/children` scan (and `CONFIG_PROC_CHILDREN`) are unnecessary on this path. Keep
  them for `--no-pid-ns`. The README's "set-user-ID or file-capability binary survives" caveat
  goes away too: PDEATHSIG on I (which never execs) is what matters, and the kernel's namespace
  teardown kills C and everything else even if C cleared its own setting.

### What the command sees

| | Now | With a PID namespace |
|---|---|---|
| `ps`, `/proc` | the host's processes | only the sandbox's (**[verified]**) |
| `kill <host pid>` | works for same-user processes | `ESRCH` (**[verified]**) |
| `$$` / `getpid()` | host pid, e.g. 114442 | 2 for the command, 3,4,... for its children (**[verified]**) |
| `$PPID` | nullroute's pid | 1 (**[verified]**) |
| `getpgrp()`, `getsid()` | real ids | 0 (**[verified]**) |
| `/proc/self/...` | host-numbered | namespace-numbered (`NSpid:\t3`) |
| debuggers/`strace -p` on host processes | blocked already (**[verified]** `environ` unreadable) | not visible at all |

Risks that follow, all **[reasoned]** unless noted:

- **`$PPID == 1`.** Some programs treat "my parent is pid 1" as "I was orphaned/daemonised" and
  exit or change behaviour. Rare in test tooling, but real. A mitigation is a second intermediate
  process so the command's parent is pid 2; not worth it unless it bites.
- **Repeating small pids.** The command is always pid 2, so scripts that build temp or lock
  names from `$$` (`/tmp/foo.$$`, pid files) collide between *concurrent* sandboxes that share
  `/tmp`. (Containers avoid this with private `/tmp`.) Mitigations: none cheap. `ns_last_pid` is
  not writable under nullroute's identity mapping (**[verified]**); `clone3` with `set_tid` to
  pick a pid is **[unverified]**; or accept and document it, and offer `--no-pid-ns`.
- **A fresh `/proc` can fail.** Containers that mask `/proc` paths can trip the kernel's "mount
  would reveal more than the existing mount hides" check; the one container configuration tried
  worked. Failure should be exit 125 with a hint to use `--no-pid-ns`, not a silent fallback to
  the host's `/proc` (which would show host pids that do not exist in the namespace).
- **The init's allocation-free requirement** after the raw `clone`. Rust runtime state after a
  raw clone is the same as after `fork` in the current `pre_exec`; keep the init to syscalls and
  stack buffers, or use option 3.
- **aarch64 / musl.** The raw `clone` argument order differs between architectures only for the
  arguments we pass as 0; CI already builds both targets, but only x86_64 runs tests
  (**[unverified]** on aarch64).
- Unprivileged user namespaces are already required; nothing new is needed for the PID namespace
  itself (**[verified]**, same host, uid 1000).

## Alternatives for the lifecycle gap

| Option | Fixes SIGKILL of nullroute? | Notes |
|---|---|---|
| Status quo (PDEATHSIG + subreaper + `kill_leftovers`) | command only; grandchildren survive (**[verified]**) | documented |
| **PID namespace** | **yes, all processes, enforced by the kernel** (**[verified]**) | the proposal |
| cgroup v2 `cgroup.kill` | **no**, see below | needs a delegated, writable cgroup and a live writer |
| A supervisor process that outlives nullroute and kills the tree on pipe EOF | mostly | racy against forks, relies on `/proc` scans and pid reuse; if it is SIGKILLed too the gap is back; extra process anyway |

**cgroup v2.** `cgroup.kill` (Linux 5.14+) SIGKILLs every process in a cgroup, but (1) nothing
triggers it when the creator dies: the kernel has no "kill this cgroup when its owner exits"
(the only automatic hook, `release_agent`, is root-only and v1), so a SIGKILLed nullroute
cannot clean up and a second surviving process would be needed, which is the original
problem; (2) an unprivileged process can create a child cgroup only inside a delegated
subtree. **[verified]** on this host: the user's own cgroup (a systemd user service) was
writable, `mkdir` and `rmdir` of an empty child succeeded, `cgroup.kill` exists, and `/sys/fs/cgroup` is
`cgroup2 … nsdelegate`. That is the systemd-user-session case. In a typical CI container the
cgroup filesystem is read-only or not delegated (**[reasoned]**, not tested), so it would
be unavailable exactly where nullroute runs in CI. It could still replace `kill_leftovers` on the
"nullroute is alive" path, but the PID namespace does that better and unconditionally.

## Phased plan

1. **Refactor, no behaviour change.** Own `clone` (without `CLONE_NEWPID`) + `exec` (F2): argv/envp
   prebuilt, error pipe, same `pre_exec` body in a function. Acceptance: whole test suite green
   unchanged, three runs, plus a test that a missing command and a non-executable command still
   give the same exit code and message (see [exit-codes.md](exit-codes.md); the refactor is the
   natural place to tag setup errors apart from exec errors).
2. **Add the namespace behind a flag (`--pid-ns`, experimental).** `CLONE_NEWPID`, fresh `/proc`,
   init loop, death pipe replacing the `getppid()` check for the init, mount namespace always.
   New tests (below). The old subreaper path stays for the default.
3. **Make it the default**, add `--no-pid-ns`, drop the "orphaned grandchildren" and
   "file-capability" paragraphs from the README's signals section and the "no PID namespace" bullet
   from "What nullroute is not" (keep "no seccomp, no resource limits, shared filesystem"), update
   `SECURITY.md`'s "shares your PID namespace" sentence and `--inspect` (a `pid` entry in the
   namespaces line). Nothing is released, so steps 2 and 3 can be done together.
4. Optional later: unique pid base (`clone3`/`set_tid`), `hidepid`, pid limits via `pids.max` (needs
   cgroups, not available unprivileged in general).

### Test plan

New (in `tests/lifecycle.rs` style, real binary, real signals):

- SIGKILL nullroute while the command has background children (`sh -c 'sleep 600 & echo $! > f; wait'`):
  within a short deadline neither the command nor the recorded grandchild pid exists (`kill(pid, 0)`
  returns `ESRCH` on the host). This is the test that fails without the namespace and passes with it.
- Same with a command that `setsid`'s its child and with one that double-forks.
- Exit status: `exit 7`, `kill -TERM $$` (143), `kill -KILL $$` (137), `--strict` and `--report-json`
  values unchanged.
- `SIGTERM`/`SIGHUP` to nullroute reach the command (existing tests) when the command is not
  pid 1.
- Early SIGINT/SIGQUIT replay (the early-signal tests) unchanged and green.
- `ps -e -o pid=` lists at most the init, the command and `ps`; `test ! -e /proc/<host pid>`;
  `$PPID` is 1; `kill -0 <host pid>` fails.
- `/proc` mount failure path: simulate with a mount-namespace where `/proc` cannot be remounted
  (hard in CI) or unit-test the error mapping.
- `--no-pid-ns` keeps the current behaviour (existing subreaper tests).
- Interactive: a pty-driven test with `bash -i` for job control (optional, **[verified]** manually).
- musl and aarch64 builds still compile (existing CI).

## Prototype

The throwaway C program (~70 lines) did: `open("/proc/<self>/status")` (the early fd);
`clone(CLONE_NEWUSER|CLONE_NEWNS|CLONE_NEWNET|CLONE_NEWPID|SIGCHLD)`; in the child:
`prctl(PR_SET_PDEATHSIG, SIGKILL)`, print `getpid/getppid/getpgrp/getsid`, write
`setgroups=deny` and the identity `uid_map`/`gid_map` through `/proc/self/`, `mount(MS_REC|MS_PRIVATE)`
on `/`, optionally `mount("proc", "/proc", "proc", MS_NOSUID|MS_NODEV|MS_NOEXEC)`, read the early
status fd, optionally install TERM/HUP handlers that `kill` the command, `fork` + `execvp` the command,
then `waitpid(-1)` in a loop until the command exits, then `kill(-1, SIGKILL)`, reap, `_exit(code)`.
The launcher waited for the child and printed how it ended. Experiments used that program, the
`unshare` tool, a Python pty driver, `sh`/`sleep` workloads, and `nullroute` itself for the baseline
runs (`cargo build --locked` of this branch).

## Unverified

- Anything on aarch64 or musl at runtime; non-Ubuntu/WSL kernels; kernels older than 5.x.
- A masked `/proc` in container setups other than the one tried.
- The file-capability binary case (`ping` here is not file-capability based).
- Programs that depend on `getpgrp()`/`getsid()`/`tcgetpgrp()` or on `$PPID != 1`.
- `clone3` with `set_tid` as a way to choose the command's pid.
- Behaviour with the real nullroute code (the numbers above are from the prototype).
