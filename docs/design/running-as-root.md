# Running as root, and inherited file descriptors

Status: **open proposal** (not implemented). Scope: what `nullroute run` should do
when it is started as uid 0, and what it should do about file descriptors the
caller left open.

Evidence tags: **[verified]** means run on the host described under
[Test host](#test-host); **[reasoned]** means derived from kernel semantics but not run;
**[unverified]** means neither.

## Summary

- As uid 0 the sandboxed command keeps a full capability set after `exec`, can
  `umount` the Docker-socket decoys, and the real `docker.sock` reappears. It still
  cannot reach the host's network. **[verified]**, as real root and as root in a user namespace.
- Cause: `run_hermetic` maps the caller's uid to the *same* uid inside the new user
  namespace (`uid uid 1`). For uid 0 that makes the command "root in its namespace",
  and exec gives root its capabilities back. A non-root uid gets none.
- Recommendation: **option B′**: map a root caller to an unprivileged id *inside* the
  namespace (`65534 0 1`) and change nothing for non-root callers. It is two changed
  lines in the existing `uid_map` code, adds no syscalls to the `pre_exec` hook, and
  puts a root caller in exactly the state a non-root caller is in now. No flag, no
  refusal. Details and the alternatives are below.
- Inherited descriptors: a socket opened before nullroute started keeps working inside
  **[verified]**. Recommendation: in the same `pre_exec` hook, mark every inherited
  *socket* above fd 2 close-on-exec, with an opt-out flag. A cheaper, blunter variant is
  `close_range(3, ~0, CLOSE_RANGE_CLOEXEC)`. Both are separate changes.

## Test host

Linux 6.6.114.1-microsoft-standard-WSL2 (x86_64), util-linux 2.39.3, Python 3.12.3,
gcc, a local Docker daemon, rustc 1.99. Passwordless `sudo -n` was already available
on this host, so the "real root" runs used it to start nullroute (nothing else was run
as root and nothing on the host was modified). The binary was `cargo build --locked`
from this branch (no source changes).

## What happens now

`sandbox.rs`, `run_hermetic`: the parent computes `uid_map = "{uid} {uid} 1"` (and the
same for gid) before forking. In the child's `pre_exec` closure:
`unshare(CLONE_NEWUSER | CLONE_NEWNET [| CLONE_NEWNS])`, write `setgroups`, `uid_map`,
`gid_map`, make mounts private and bind the decoys (`hide::apply_in_child`), bring `lo`
up, hand listeners to the parent, re-arm the parent-death signal, restore the signal
mask, return. std then `exec`s the command.

Why a non-root caller ends up harmless: after `unshare(CLONE_NEWUSER)` the child has
every capability *in the new namespace*, but at `exec` a process whose euid is not the
namespace's root (uid 0 inside) has its permitted/effective sets cleared. The caller's
uid is mapped to itself, so it is not root inside and keeps nothing (`CapEff` is all
zeros in the baseline run below).

Why a root caller does not: uid 0 maps to uid 0 inside, which *is* the namespace's root.
Exec of a root process grants it the full bounding set, and the bounding set of a freshly
created user namespace is full (`CapBnd` was `000001ffffffffff` inside, **[verified]**). So
the command gets all capabilities in the sandbox's user namespace, including
`CAP_SYS_ADMIN` over the sandbox's mount namespace (the namespace that holds the decoys)
and `CAP_NET_ADMIN` over its network namespace. The README already says this ("Running
nullroute as root", in "What nullroute is not"); this note quantifies it and proposes a fix.

## Experiments (root)

All run with a probe that prints uid and capability sets, connects to `/run/docker.sock`
(sends `GET /_ping`, the daemon's read-only health check), tries `umount2` on it, and
connects again. Sandbox: `nullroute run -- python3 probe.py`, default sockets (the decoy
answers `403`).

| Caller | uid / CapEff inside | `/run/docker.sock` before | `umount2` | after |
|---|---|---|---|---|
| uid 1000 (baseline) | 1000 / `0000000000000000` | `403 Forbidden` (decoy) | `EPERM` | `403` |
| `unshare --user --map-root-user nullroute run …` (root without real root) | 0 / `000001ffffffffff` | `403` | **ok** | **`200 OK` from the real daemon** |
| real root (`sudo -n nullroute run …`) | 0 / `000001ffffffffff` | `403` | **ok** | **`200 OK` from the real daemon** |

So `unshare -Ur` is a faithful, privilege-free reproduction of the root case: same
result as real root. **[verified]** (The `200 OK` is the daemon answering `GET /_ping`;
nothing was started or changed through it.)

Still contained in the root case:

- Host network **[verified]**: `connect(127.0.0.1:<port of a host listener>)` from inside gets
  `ECONNREFUSED` (the sandbox's own loopback), as uid 1000 and as real root. With a
  *pre-opened* host netns fd inherited (see the fd section), `setns(fd, CLONE_NEWNET)`
  fails with `EPERM` for both: the command's capabilities are only valid in the sandbox's
  user namespace, not in the initial one that owns the host network namespace.
- Other processes **[verified]** for uid 1000 inside the sandbox: `open("/proc/<nullroute
  pid>/ns/net")` is denied (`EACCES`), `/proc/<pid>/environ` and `/proc/<pid>/root` of an
  unrelated host process of the same user are not accessible, and `kill -0` on that process
  succeeds (so "can see and signal your other processes" in the README is accurate). For
  root the `ns/net` open was denied as well; the rest was not run as root.
- Files **[verified]** (throwaway prototype of the `pre_exec` setup, real root): root inside is
  not the host's root for files owned by *other* users. With `CAP_DAC_OVERRIDE` only in the
  sandbox's namespace, and only uid 0 mapped, a 0600 file owned by uid 1000 is unreadable
  and unwritable (`EACCES`). Files owned by root stay accessible as they are to the caller
  (read `/etc/shadow`, write a root-owned 0600 file: both fine). So the exposure from root is
  "decoys and namespace-local privileges", not "the host's root powers".

Container check **[verified]**: in a default Docker container (alpine image, local daemon,
`--network none`), `unshare -Ur true` as container root fails with `EPERM` (the default
seccomp profile blocks `unshare(CLONE_NEWUSER)` without `CAP_SYS_ADMIN`), and also as
`--user 1000`. So on the common "root CI container" setup nullroute cannot start at all
(it should exit 125 with the user-namespace hint, by the code path in `explain_spawn_error`;
nullroute itself was not run inside a container). The root case matters on privileged or
seccomp-relaxed containers, on VMs/runners where jobs run as root, and for `sudo nullroute …`.

## What the attack is

A root caller's command can, from inside the sandbox, unmount any decoy or mask and use
the underlying socket. That reopens exactly the things the sockets section of the README
closes: `docker.sock` (containers with full network), the system D-Bus and
systemd-resolved's varlink socket (name resolution on the host's behalf, so DNS leaks),
nscd. It can also reconfigure its own network namespace (irrelevant: there is nothing to
connect to) and mount filesystems in its own mount namespace. It cannot leave the network
namespace. The README says the resolver masks "can't be opted back in"; for a root caller
that is not true now. Only the Docker decoy was exercised in the experiments; the others
use the same mount mechanism (**[reasoned]**).

## Options

### A. Refuse to run as uid 0

`main` (or the start of `run_hermetic`) checks `geteuid() == 0` and exits, with an
override flag (`--allow-root` or similar) for people who accept the exposure.

- Exit code: **125** under the policy proposed in [exit-codes.md](exit-codes.md) (the sandbox
  will not be set up; the arguments are fine). Not 2.
- Breaks: `sudo nullroute run …` workflows, CI jobs that run as root on a VM or runner,
  privileged Docker-in-Docker jobs. In default root containers it changes nothing (they
  cannot start anyway). Every one of those users needs the override flag, and the override
  re-enables the hole, so the people most likely to hit it end up with no protection.
- Closes: the attack, for everyone who does not pass the flag.
- Implementation: about ten lines in `main.rs`, no `pre_exec` changes. Test:
  `unshare -Ur nullroute run -- true` exits 125 with a message; with the flag it behaves as now.

### B. Run, but make root unprivileged inside the sandbox

Two ways, both applied only when the caller's uid is 0.

**B′: map root to an unprivileged id (recommended).** Write `65534 0 1` (inside id 65534,
outside id 0) instead of `0 0 1` into `uid_map`, and likewise into `gid_map` when the gid
is 0 too. After exec the command's euid is not the namespace's root (inside, uid 0 is not
even mapped), so it gets no capabilities, which is the same mechanism that already protects
non-root callers. No new syscalls.

**B1: keep uid 0 but strip capabilities** in `pre_exec` after all setup, before the final
`die_with_parent` re-arm: `prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL)`, loop
`PR_CAPBSET_DROP` over every capability (read the highest from `PR_CAPBSET_READ` until
`EINVAL`), `prctl(PR_SET_SECUREBITS, SECBIT_NOROOT | SECBIT_NOROOT_LOCKED)`, optionally
`PR_SET_NO_NEW_PRIVS`. All are plain syscalls with integer arguments, so they are
async-signal-safe. A new user namespace resets the bounding set and securebits to
defaults, so this has to run after the `unshare`, which it does.

Emulated under real root, **[verified]** (the first four rows run through `nullroute run`
with `setpriv`/`unshare` inside to apply the state a `pre_exec` implementation would;
the last row with a throwaway C program that mimics the `pre_exec` setup):

| Variant | uid / CapEff inside | `umount2` of the decoy | decoy afterwards |
|---|---|---|---|
| plain (current) | 0 / `000001ffffffffff` | ok | real socket (`200`) |
| `no_new_privs` only | 0 / `000001ffffffffff` | **ok** | real socket (`200`) |
| bounding set dropped + securebits `noroot` (B1) | 0 / `0000000000000000` | `EPERM` | decoy (`403`) |
| nested user namespace, root → 65534 (like B′) | 65534 / `0000000000000000` | `EPERM` | decoy (`403`) |
| prototype, `uid_map` = `65534 0 1` (B′) | 65534 / `0000000000000000` | `EPERM` | decoy |

Notes from those runs, which decide between B′ and B1:

- `no_new_privs` alone does **not** help: root keeps the capabilities it already holds. Do
  not propose it as the fix.
- Under B1 the command is still uid 0 but cannot create a nested user namespace that maps
  root: `unshare -r` fails writing `uid_map` with `EPERM` **[verified]**. The reason is
  presumably the kernel rule that writing a map whose outer id is 0 needs `CAP_SETFCAP` in
  the parent namespace **[reasoned]**. Rootless tooling inside the sandbox (bubblewrap,
  rootless Podman, `unshare -r`-based test fixtures) would break for root callers. Under B′
  the nested `unshare -Ur` works exactly as it does for uid 1000, and the nested `umount` of
  the decoy still fails (`must be superuser to unmount`). **[verified]**
- Files under B′ **[verified]** (prototype): root-owned files stay readable/writable as the
  owner (the kernel compares the kuid, which is still 0), and other users' files stay
  inaccessible, the same as with root now.

What B′ changes for users: `id -u` and `whoami` inside report 65534/`nobody` for a root
caller, and everything the command creates is still owned by real root on disk. Scripts
that branch on "am I root" take the non-root branch. `HOME`, `PATH` and the environment are
unchanged. `apt`/`chown`/`mount`-style tools fail with `EPERM`, but they already could
not do anything useful (no network, no capabilities outside the sandbox's namespace).

B′ depends on the same kernel rule as above: writing a map whose outer id is 0 needs the
*parent* to have held `CAP_SETFCAP`. The current `0 0 1` has the identical requirement, so no
new failure mode appears (a root caller without that capability fails closed, as now).
**[reasoned]**; not separately tested.

### C. Document only

Keep the current behaviour and the README bullet. Cost: zero. Leaves a hole in a stated
guarantee (masks "can't be opted back in") for every `sudo nullroute` user, and the
documentation is the only protection.

## Recommendation

**B′**, unconditionally for uid 0, no flag:

- Smallest change: it reuses the `uid_map` write that already exists.
- Same end state as a non-root caller, which is the case the test suite and the README
  already describe, so there is nothing new to explain except one README bullet.
- Keeps `sudo nullroute …` and root CI jobs working (they just stop being root inside).
- Nested user namespaces keep working (unlike B1).
- Does not depend on a flag nobody will pass.

If B′ turns out to break a real workflow, B1 is the fallback. A is the strictest and the
the one to do last, because its override flag recreates the hole.

### Implementation sketch (not applied)

`sandbox.rs`, in `run_hermetic`, replacing the two `format!` lines:

```diff
-    let uid_map = format!("{uid} {uid} 1\n");
-    let gid_map = format!("{gid} {gid} 1\n");
+    // A uid-0 caller would be root in its own namespace and get all capabilities
+    // back at exec (docs/design/running-as-root.md). Show it as an unprivileged id.
+    let in_uid = if uid == 0 { UNPRIVILEGED_ID } else { uid };
+    let in_gid = if uid == 0 && gid == 0 { UNPRIVILEGED_ID } else { gid };
+    let uid_map = format!("{in_uid} {uid} 1\n");
+    let gid_map = format!("{in_gid} {gid} 1\n");
```

with `const UNPRIVILEGED_ID: u32 = 65534;`. The condition is on `uid == 0`, the id that
matters for the capability computation; a non-root caller whose primary gid is 0 keeps its
identity gid map, since gid 0 carries no capabilities. Both strings are built before fork,
so the `pre_exec` closure is unchanged: no new syscalls, nothing allocating in the hook,
and nothing that touches the PDEATHSIG logic in `lifecycle.rs` or the signal logic in
`signals.rs` (neither looks at ids). For B1 instead, the capability drop would be a new
function next to `die_with_parent` in `lifecycle.rs`-style raw-syscall code, called from the
closure after `listen_and_send`; still async-signal-safe, but a second place that must stay
that way.

Other places: `inspect.rs` could show `uid: 0 -> 65534 (no capabilities)`; the README
bullets under "What nullroute is not" and "How it works" (steps 2 and 4) and the
Requirements paragraph ("run nullroute as an ordinary user, not root") become "a root
caller is shown as `nobody` inside"; `CONTRIBUTING.md` still says to run the tests as an
ordinary user, which stays true.

### Test plan

1. New `tests/root.rs`, no real root needed: run
   `unshare --user --map-root-user <nullroute> run -- sh -c 'id -u; grep CapEff /proc/self/status'`
   and assert inside uid is 65534 and `CapEff` is `0000000000000000`. Skip (with a
   "skipping" line, like the Docker tests) when `unshare` is missing or user namespaces
   are refused.
2. Same wrapper, with a Unix listener the test creates in a temp dir and `--hide-socket`
   for it: inside, assert the decoy still answers after the command tries `umount` (the
   test command can be `python3 -c` with `ctypes` or the `umount` binary), instead of
   depending on a real Docker daemon.
3. Optional job when passwordless sudo exists (GitHub's runners have it; the CI file
   already uses `sudo sysctl`): the same two assertions with `sudo -n`, gated on
   `sudo -n true`.
4. Regression: existing tests unchanged for uid != 0; assert a non-root run still maps
   `id -u` to the caller's uid.
5. `--inspect` golden output if the line is added.

## Inherited file descriptors

A descriptor that is open in nullroute's parent and not close-on-exec is inherited by
nullroute and then by the command. (Rust std opens its own descriptors with `O_CLOEXEC`, so
nullroute adds none of its own; **[reasoned]**.) A socket belongs to the network namespace it
was created in, so one the caller opened earlier keeps talking to the host network.

**[verified]**: with fd 8 a TCP connection to a host listener on `127.0.0.1:38765`, opened by
the calling shell, `nullroute run -- python3 …` could `sendall`/`recv` on fd 8 and got
`HTTP/1.0 200 OK` from the host server, while a fresh `connect(127.0.0.1:38765)` from inside
got `ECONNREFUSED`. The probe's descriptor list also showed fd 3, which matches a socket the tool harness leaves
open (checked separately: fd 3 is a socket in the harness's shell), so an accidentally inherited
socket reached the command too and the gap shows up without trying. An inherited host netns fd
(fd 9, `/proc/self/ns/net`) cannot be entered: `setns` returns `EPERM`. (The same socket test
as real root was inconclusive because `sudo` closes descriptors above 2 before running the
command; there is no reason to expect a different result, but it was not demonstrated.)
The README documents this as a known limit.

Other kinds of inherited descriptors that matter for the same reason **[reasoned]**:
connected Unix sockets (a connection already made to the real Docker daemon survives the
decoy mount), listening sockets passed for socket activation (`LISTEN_FDS`), and sockets
registered with an io_uring instance created outside (**[unverified]**). Descriptors 0–2 are
never touched: if stdout is a socket (`ssh`, some CI log shippers), it stays usable by design.

### Options

1. **`close_range(3, ~0u, CLOSE_RANGE_CLOEXEC)` in `pre_exec`.** One syscall (Linux 5.11+,
   `libc::SYS_close_range`), async-signal-safe, marks every inherited fd ≥ 3 close-on-exec so
   it disappears at `exec`. The flag matters: *closing* the range would also close std's
   internal "report the exec error" pipe and break error reporting (a failed exec would
   look like success). Measured: 1 µs for the call (the same call without
   `CLOSE_RANGE_CLOEXEC` semantics was not tried); the portable fallback (loop
   `fcntl(F_GETFD)` over `3..RLIMIT_NOFILE`) took 175 ms with `RLIMIT_NOFILE` = 1 048 576
   (Docker's default), so a fallback must be bounded, or simply be an error ("fail closed")
   on kernels without `close_range`.
2. **Sockets only.** Enumerate `/proc/self/fd` with raw `open` + `getdents64` into a stack
   buffer (the `/proc` seen at that point is the host's, because no PID namespace exists
   yet; see [pid-namespace.md](pid-namespace.md) if that changes), `fstat` each fd ≥ 3 and
   set `FD_CLOEXEC` on those with `S_ISSOCK`. Async-signal-safe as long as nothing
   allocates. Falls back to option 1 if `/proc/self/fd` cannot be opened.
3. **Document only** (the current state).

Trade-offs:

| | Option 1 (all fds ≥ 3) | Option 2 (sockets) |
|---|---|---|
| Closes pre-opened network sockets | yes | yes |
| Breaks fd-inheritance conventions | yes: `make`/`cargo` jobserver pipes (make falls back to `-j1`), `3>file` redirections the command expects, test harnesses that talk over fd 3 | no, pipes and files survive |
| Breaks socket activation / harness-reserved ports | yes | yes (the point; opt-out flag) |
| Code | one syscall | about 40 lines of `getdents64` parsing |
| Failure mode on old kernels | needs fallback or error | needs `/proc` (the sandbox already reads it) |

Not run: the make/jobserver and `LISTEN_FDS` claims are **[reasoned]**.

Opt-out: `--inherit-sockets` (name open) for callers that pass a socket on purpose. Since
nothing is released, shipping the sweep as the default with the opt-out is the cheapest time
to do it; if the jobserver case is considered important, prefer option 2.

Placement in `pre_exec`: after `child_side.listen_and_send()` (the socketpair to the parent
is still needed until then) and before the last `die_with_parent`/`restore`. Sweep with
`CLOEXEC`, not `close`, so nothing the closure still uses disappears under it.

Test plan: a harness opens a TCP socket to a local listener (and a Unix connection to a
listener it also created) and passes the descriptor numbers in the environment; assert the
command cannot use them by default and can with `--inherit-sockets`; assert pipes on fd 3
survive under option 2; assert fds 0–2 are untouched.

## What stays out of scope

A hostile root caller who controls the nullroute binary or its environment is not a threat
model for this tool (the README says as much for hostile code in general). This note only
covers an honest `sudo nullroute` or a root CI job, and descriptors that something other
than nullroute left open.

## Unverified

- Real root inside a container (only the user-namespace refusal was checked, and not through nullroute).
- The `CAP_SETFCAP` condition for B′, in a hardened container or otherwise.
- io_uring-registered sockets, `LISTEN_FDS`, jobserver behaviour.
- Fd inheritance as *real root* (blocked by `sudo` closing fds).
- Masks other than the Docker decoy (D-Bus, resolved, nscd) being unmountable by root (same mechanism).
- Any real-world tooling reaction to "root appears as nobody".

## Reproducing

```bash
# root in a user namespace, no real root needed
unshare --user --map-root-user ./target/debug/nullroute run -- python3 probe.py
# inherited socket: the shell opens fd 8 to a host listener, then
( exec 8<>/dev/tcp/127.0.0.1/PORT; ./target/debug/nullroute run -- python3 use_fd8.py )
```

The B′ prototype was about 20 lines of C: `unshare(CLONE_NEWUSER|CLONE_NEWNS|CLONE_NEWNET)`,
write `deny` to `/proc/self/setgroups`, `65534 <uid> 1` to `uid_map` and `65534 <gid> 1` to
`gid_map`, `mount("none", "/", NULL, MS_REC|MS_PRIVATE, NULL)`, bind-mount a decoy file over a
target file, `execvp` a probe that tries `umount2(target)`. Run as real root with inside id 0
it unmounts the decoy; with inside id 65534 it gets `EPERM`. It was deleted after use.
