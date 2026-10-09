# Robustness: diagnostics, signals, scratch files, caps

Decisions behind the robustness fixes, and what was deliberately left open.

## Diagnostics never change a run

Everything nullroute writes for a human (warnings, live "blocked ..." lines,
the summary, error messages, `--inspect`) goes through `diag!` / `diagln!`
(src/diag.rs), which drop the message if stderr can't be written. Rust ignores
SIGPIPE, so `eprintln!` turns a closed pipe or a full disk into a panic: exit
101 instead of the command's status, and a dead worker thread. The `--dry-run`
listing on stdout is the command's *result*, not a diagnostic: it dies by
SIGPIPE like `ls` and reports other write errors with exit 74. Guards:
tests/no_raw_prints.rs and clippy's `print_stdout`/`print_stderr` lints.

## Signals

nullroute blocks SIGINT/SIGQUIT/SIGTERM/SIGHUP in its main thread before it
creates anything, so every later thread inherits the block, and one thread takes
them with `sigwaitinfo` (nothing runs in signal-handler context).

**Group or pid.** `kill -TERM -PGID` and `timeout` signal the whole process
group, which contains the command; forwarding as well delivers it twice. The
kernel gives no way to tell the two apart (the `siginfo` is identical), so a
*sentinel* does: a child forked into the group that blocks the four signals and
reports which are pending when asked. A group-directed signal reaches it; a
pid-directed one doesn't.

- The group is signalled newest member first, so a sentinel forked after
  nullroute has the signal before nullroute does. This is an implementation
  detail of the kernel, not an ABI promise. If it ever changed the failure mode
  is a duplicate forward (the old behaviour), not a lost signal. Settle time
  (5 ms) and batching (everything pending is handled as one decision, so a
  second system call by the same sender - `timeout` signals its child and then
  its group - counts as one signal) make it reliable in practice.
- No sentinel (fork failed, it died, it stopped answering): signals are
  forwarded unconditionally.
- A command that left the process group is always forwarded to: it never got
  the group's signal.
- Not solved: two signals sent far enough apart are two signals; both reach the
  command.

**Never signalling a recycled pid.** The main thread waits for the command with
`waitid(WNOWAIT)` (it stays a zombie, so its pid can't be reused), clears the
pid under the lock the forwarder holds while it sends, and only then reaps. Unit
tests: signals::tests.

## Scratch files

The decoy sockets and the generated resolv.conf have to exist as files to be
bind-mounted, so they live in a directory in the temp dir. Options considered:

- *tmpfs/private mount owned by the sandbox*: the files are needed in the
  parent's mount namespace before the child exists; creating a mount namespace
  for nullroute itself would change what it sees.
- *memfd / O_TMPFILE*: a bind mount needs a path in a mount of this namespace;
  a memfd's internal mount isn't one (`EINVAL`).
- *unlink after use*: done. A bind mount keeps the file alive, so the directory
  is removed right after spawn returns, i.e. after the child made its mounts.
- *janitor*: done for what remains (a kill between creating the directory and
  the end of spawn). The "in use" marker is an exclusive `flock` that the kernel
  drops when the process dies, not a pid (no pid reuse, works across PID
  namespaces); stale means named like ours, owned by the user, mode 0700, over a
  minute old (guards a nullroute from before the lock existed) and lockable.

## Caps

Per listener: at most 256 connections at a time (DNS over TCP 64, decoys 32);
another is closed at once. A thread that can't be started drops the connection;
an accept error backs off (20 ms) instead of spinning. DNS over TCP: 10 s idle,
30 s total, 64 queries per connection. Proxy name lookups: 10 s, at most 32 in
flight. Report: 1000 distinct targets, 20 live lines per second; the rest is
counted ("not_listed" in the JSON), still blocks for `--strict`.

Test hooks (debug builds only; those tests are `#[ignore]`d in release):
`NULLROUTE_TEST_MAX_CONNECTIONS`, `NULLROUTE_TEST_REPORT_LIMITS`,
`NULLROUTE_TEST_HOLD_BEFORE_SPAWN`.

### Open

- **Idle timeouts on relayed data.** Connections through `--port` and the proxy
  have no idle timeout: a database connection pool is idle for hours, and
  closing it would break working setups. The connection cap is the bound.
  A configurable idle timeout (`--idle-timeout`) would be the proposal.
- **Total thread budget.** The caps are per listener; many listeners times
  256 can still exceed a low `RLIMIT_NPROC`. Each failure is handled (the
  connection is dropped, reported once), but there is no global budget.
- **A global soft cap on the report's memory** other than the entry count: a
  single target string can be as long as the request allows.
