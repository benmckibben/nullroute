# Exit codes: what they are, where they are inconsistent, and a consistent policy

> **Update (implemented):** PR A (>64 `--port` values now exit 2) and PR B (an unknown option
> after `run` is a usage error, exit 2; a missing command exits 127 and a non-executable one 126,
> without the user-namespace hint; `--dry-run | head` ends by SIGPIPE instead of a panic) have
> landed. The text below is the original analysis, kept as written, so it describes the code
> *before* those changes. **Still open:** `--dry-run` accepts a configuration the real run rejects
> with 125 ("too many listeners"), and the "failed to run" wording is also used for failures
> after the command has started.

Status: proposal (nothing here is implemented in this PR). Scope: document the exit codes
nullroute produces today by reading the code and running the binary, list the places where the
behaviour contradicts its documented meaning or the README contradicts itself, and propose one
policy plus the exact follow-up changes.

Evidence tags: **[verified]** = I ran it (commands in the table; the binary is
`cargo build --locked` of this branch, no source changes); **[reasoned]** = from reading the
code, not run; **[unverified]** = neither.

## Summary

- Two codes carry nullroute's own "could not do it" meaning: **2** (bad arguments, nothing run)
  and **125** (nullroute itself failed). The README says unknown options and a `--port` value
  "that can't work" give 2, and also says "more than 64 `--port` values" gives 125.
  The code does what the second sentence says, so **the README contradicts itself**, and the
  >64 case is the odd one out among the argument errors. **[verified]**
- More inconsistencies found: an unknown option after `run` is taken as the *command* and exits
  125 (the README says 2); `--dry-run` accepts a configuration the real run rejects with 125
  ("too many listeners"); a command that exists but is not executable gets 125 *and* a message about
  user namespaces; a command that cannot be found or executed gets 125 where Docker/shells give
  127/126; `--dry-run | head` can end in a Rust panic (101). Full list below.
- Proposed policy: **2 = the invocation is wrong (decidable from the arguments), 125 = nullroute
  could not set up or launch the sandbox for reasons outside the arguments**, plus (optional,
  recommended) 127/126 for "command not found / not executable". Nothing is released, so this is
  the cheapest time to change it.
- Follow-up: PR A (tiny): >64 ports → 2. PR B: the rest. Both are specified below with diffs; the
  PR A and the `last = true` part of PR B were applied to a scratch copy and tested; the rest
  is sketched.

On "nothing released": `CHANGELOG.md` says "Nothing has been released yet". `Cargo.toml` says
`version = "0.1.0"` (not the `0.0.0` placeholder the task description mentioned); I did not check
crates.io, and did not need to.

## The table as implemented

Where: all codes are produced in `src/main.rs` (`main`, `run`) or by clap before `main`'s body;
`src/lifecycle.rs` has one `_exit(128 + SIGKILL)` in the forked child that nobody observes.
Every row was produced by running the command.

| Code | Trigger | Run (verified unless noted) | Documented as |
|---|---|---|---|
| 0 | command succeeded; `--dry-run`; `--help`; `--version` | `run -- true`, `run --dry-run -- true`, `--version` | pass-through |
| 1 | `--strict` and something was blocked, command had exited 0 | `run --strict -- python3 -c "…connect('/run/docker.sock')…"; exit 0` → 1 | 1 (README, flag help) |
| 1 | `_ => 1` fallback in `run()` when a child status is neither exit nor signal | **[reasoned]**; not reachable without ptrace-stop | undocumented |
| 2 | clap: no subcommand, no command, invalid value (`--port 0`, `--port 70000`, `--seal-docker-pulls bogus`), unknown option **before** `run` | `nullroute`, `nullroute run`, `run --port 0 -- true`, `run --seal-docker-pulls bogus -- true` | "bad arguments … unknown or invalid options" |
| 2 | `--seal-docker-pulls` without a sealed socket | `run --seal-docker-pulls none -- true` | yes |
| 2 | `--allow` entry that can never work | `run --allow localhost -- true` | yes |
| 2 | `--resolve` for a host not in `--allow` | `run --resolve foo:1.2.3.4 -- true` | yes |
| 2 | more than 254 exact `--allow` names for the sinkhole | 300 names → `too many --allow host names…` | yes (generic) |
| 2 | `--port 53` with the sinkhole on | `run --allow x.example --port 53 -- true` | yes |
| 2 | `--report-json` path not writable | `run --report-json /nonexistent/x.json -- true` | yes |
| **125** | **more than 64 `--port` values** | 65 ports → `nullroute: at most 64 --port values` (also with `--dry-run`); 64 ports → 0 | **both 2 and 125 (README contradicts itself)** |
| 125 | `hide::plan` failed (temp dir, bind) | `TMPDIR=/nonexistent run -- true` → `preparing socket hiding: No such file…` | yes ("socket hiding couldn't be prepared") |
| 125 | command not found | `run -- /nonexistent/cmd` → `failed to run "/nonexistent/cmd": No such file or directory` | yes |
| 125 | command not executable | `run -- /etc/passwd` → `failed to run "/etc/passwd": Permission denied (os error 13): could not create an unprivileged user namespace. On Ubuntu 23.10+ …` | yes, but the message is wrong |
| 125 | unknown option **after** `run` (taken as the command) | `run --bogus -- true`, `run --strcit -- true`, `run -x -- true` → `failed to run "--bogus"…` | **README says 2** |
| 125 | too many listeners (1024) | one `--allow` host with 1100 ports → `failed to run "true": too many listeners (1104 > 1024)`; `--dry-run` with the same flags → **0** | not documented; message says "failed to run" |
| 125 | user namespaces refused (`EPERM`/`EACCES`/`ENOSPC` from spawn) | **[unverified]** here (this host allows them); same path as the `EACCES` row | yes |
| 125 | `Sinkhole`/`hide` start or handover failed after the command started | **[reasoned]** (`h.start`, `parent.receive` in `run_hermetic`: the command is killed and the error reported as "failed to run") | yes (generic) |
| 74 | `--report-json` could not be written at the end, command exit 0 | `run --report-json /dev/full -- true` | yes |
| 128+N | command killed by signal N | `sh -c 'kill -TERM $$'` → 143; `kill -INT $$` → 130 | yes |
| any | command's own code (including 125, 126, 127) | `sh -c 'exit 125'` → 125; `exit 126` → 126; `exit 127` → 127 | yes ("can exit with any of these itself") |
| 101 | Rust panic when stdout is closed: `run --port 1,…,64 --dry-run -- true \| head -1` | → 101, `failed printing to stdout: Broken pipe` | undocumented |

nullroute itself never produces 126 or 127. **[verified]** by reading all `ExitCode` uses (all in
`main.rs`) and by the table: the not-found and not-executable rows give 125.

For comparison **[verified]** with a local Docker daemon (`alpine` image already present, `--network none`):
`docker run … /nonexistent` → **127**, `docker run … /etc/passwd` → **126**, `docker run --bogus-flag …` →
**125**. So Docker's 125 means "the CLI/daemon failed", usage errors included, and its 126/127 mean
"the contained command could not be invoked / found". The README's analogy ("125 is what Docker and Podman use for
'the runner failed'") is right for the runner, but nullroute folds the 126/127 cases into 125 and
sends usage errors to 2, which is the convention for ordinary CLIs and for clap, unlike Docker.

## Inconsistencies

1. **`>64 --port` → 125.** Every other bad `--port` (0, 70000, non-numeric, 53 with the sinkhole)
   exits 2; the count limit is also a property of the arguments alone. The README's table lists it
   under 125 *and* describes 2 as covering a "`--port` value that can't work". Nothing tests it
   (`grep` for "at most" in `tests/` finds nothing; `tests/ports.rs` only checks that bad single
   values give 2). **[verified]**
2. **Unknown option after `run` → 125.** `argv` is declared with `trailing_var_arg` and
   `allow_hyphen_values`, so `run --strcit -- pytest` is parsed as command `--strcit` with arguments
   `-- pytest`. Result: exit 125 and `failed to run "--strcit": No such file or directory`, where the README
   promises 2 ("unknown or invalid options") and a typo in a flag looks like a broken sandbox.
   It fails closed (the typo'd command does not exist), but the exit code and message are
   misleading. Also, `run --strict true` (no `--`) is accepted and runs `true` (exit 0), so the README's
   "put the command after `--`" is not enforced. **[verified]**
3. **`--dry-run` accepts what the real run rejects.** Listener count (`MAX_LISTENERS` = 1024) is
   checked in `forward::prepare`, i.e. only on a real run, as a late 125 with "failed to run". A
   user who validates a configuration with `--dry-run` gets 0, then a failure in CI. The limit is a
   property of the arguments, so it belongs with the 2s and before `--dry-run` returns. **[verified]**
4. **Not found / not executable → 125, where shells and Docker use 127/126.** README documents it, so it
   is not a bug, but it makes "I typo'd the command" and "the sandbox is broken" indistinguishable
   for a CI script, which is the distinction 125 was chosen to provide. It is also the reason the
   README warns that the command may itself exit with these codes. **[verified]**
5. **Misleading message for `EACCES` from `exec`.** `explain_spawn_error` turns any `EPERM`/`EACCES`/`ENOSPC`
   from `spawn` into the user-namespace hint, but `spawn` also reports exec failures: running a file without
   the execute bit prints a message about AppArmor. The exit code is fine; the message is wrong.
   **[verified]**
6. **Panic (101) on a closed stdout.** `--dry-run` uses `println!`, and Rust ignores `SIGPIPE` at
   startup, so a reader that exits early turns into a panic message and 101, an exit code that is
   documented nowhere and means "Rust panic". **[verified]** (needs enough output to outrun the pipe).
7. **"failed to run" is used for everything after `run_hermetic` starts**, including failures after the
   command was already running (sinkhole start, handover), so the text is not always true. Cosmetic.
   **[reasoned]**

Observations that are *not* proposed as changes, but worth a decision:

- `--hide-socket /typo` prints `no such file, ignoring` and exits 0; `--allow-socket /typo` is silent.
  A mistyped `--hide-socket` leaves the socket reachable. That is deliberate (default hide
  lists name paths that don't exist on most machines), but the explicit-flag case could be an
  exit-2 error or at least count under `--strict`. **[verified]** (exit 0 both).
- Exit 1 for `--strict` collides with a command that exits 1 by design; documented, and `--report-json`
  records `strict_failed` for disambiguation.
- 74 only replaces a would-be 0; documented.

## Proposed policy

| Code | Meaning (proposed wording) |
|---|---|
| 0 | the command succeeded (and `--strict` found nothing blocked), or `--dry-run`/`--help`/`--version` succeeded |
| 1 | `--strict`: the command succeeded but something was blocked |
| **2** | **usage error: the command line is invalid. Decided from the arguments alone, before anything runs.** Unknown/invalid options, missing command, values that cannot work, conflicting options, argument limits (`--port` count, `--allow` names, listener count), an unwritable `--report-json` path |
| 74 | the report could not be written after a run that would have exited 0 |
| **125** | **nullroute could not set up or launch the sandbox for a reason outside the arguments**: user namespaces refused, temp dir or socket creation failed, handover failed |
| 126 | (proposed) the command exists but could not be executed |
| 127 | (proposed) the command was not found |
| 128+N | the command was killed by signal N |
| other | the command's own exit code |

Rule of thumb for contributors: *would the same arguments work on a host where namespaces work?* If not,
it is 2; if the arguments are fine and this host or run failed, it is 125.

126/127 are the optional part. For: matches Docker, `sh`, `env`, `timeout`, `nohup`; separates a typo from a
broken sandbox. Against: the codes are shared with commands that exit with them; needs the setup errors
told apart from exec errors (below). Since a script cannot tell "125 from the command" from "125 from nullroute"
either, I think the separation is worth more than the (already existing) ambiguity. Recommend adopting them,
in PR B.

## Compatibility cost

None for users of a release, because there is no release. Within the repository: nothing asserts the >64 code
(`grep` found no test), `tests/hermetic.rs` asserts `Some(125)` for a missing command (changes only if
126/127 are adopted), the README table and `main.rs`'s comment on 125 describe the old behaviour, and the
CHANGELOG's "Added" bullet says "`125` if nullroute itself fails" (still true). Scripts written against the
README that treat 125 as "retry elsewhere" are unaffected for the setup failures; those that special-case a
missing command (125 → 127) are the only ones that would notice, and only once there is a release. If a release
happens first, changing it afterwards means a CHANGELOG "Changed" entry and a minor version at least.

## PR A: >64 ports is a usage error (applied to a scratch copy and tested)

`src/main.rs` (the block after the `--port 53` check):

```diff
             if ports.len() > forward::MAX_PORTS {
-                eprintln!("nullroute: at most {} --port values", forward::MAX_PORTS);
-                return ExitCode::from(125);
+                eprintln!(
+                    "nullroute: at most {} --port values (got {})",
+                    forward::MAX_PORTS,
+                    ports.len()
+                );
+                return ExitCode::from(2);
             }
```

(Optionally replace the bare `2`/`125`/`74`/`1` literals with named constants next to the existing
`EXIT_REPORT_WRITE_FAILED`: `EXIT_USAGE: u8 = 2`, `EXIT_SANDBOX: u8 = 125`.) Check result in the scratch copy
**[verified]**: 65 ports → exit 2 with `at most 64 --port values (got 65)` both with and without `--dry-run`; 64 ports → 0.

`tests/ports.rs`, next to `invalid_ports_are_rejected_before_running` (sketch):

```rust
#[test]
fn too_many_ports_is_a_usage_error() {
    let many = (1..=65).map(|p| p.to_string()).collect::<Vec<_>>().join(",");
    for extra in [&[][..], &["--dry-run"][..]] {
        let o = Command::new(env!("CARGO_BIN_EXE_nullroute"))
            .args(["run", "--port", &many])
            .args(extra)
            .args(["--", "true"])
            .output()
            .unwrap();
        assert_eq!(o.status.code(), Some(2), "{extra:?}: {o:?}");
        assert!(String::from_utf8_lossy(&o.stderr).contains("at most 64 --port values"));
    }
    let ok = (1..=64).map(|p| p.to_string()).collect::<Vec<_>>().join(",");
    let o = Command::new(env!("CARGO_BIN_EXE_nullroute"))
        .args(["run", "--dry-run", "--port", &ok, "--", "true"])
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(0), "{o:?}");
}
```

README: in the exit-code table add "more than 64 `--port` values" to row **2** and delete "or more than 64
`--port` values were given" from row **125**; the sentence "At most 64 ports can be bridged." stays.
CHANGELOG, under "Added", in the first bullet's exit-code clause or as a new sub-line: "exit code 2 for every
invalid invocation, including more than 64 `--port` values; 125 only when the sandbox itself can't be set up".
(While nothing is released, no "Changed" entry is needed.)

## PR B: the rest

1. **Unknown options after `run` → 2** (verified in the scratch copy, all of the following).
   `src/main.rs`:

   ```diff
   -        #[arg(required = true, trailing_var_arg = true, allow_hyphen_values = true)]
   +        #[arg(required = true, last = true)]
            argv: Vec<String>,
   ```

   Results **[verified]**: `run --bogus -- true` → 2 with clap's "unexpected argument '--bogus' found", `run --strcit -- true` → 2
   with "a similar argument exists: '--strict'", `run -- true` → 0, `run -- --version` → runs a command named `--version`
   (125, not found, as it should), `run true` (no `--`) → 2 "unexpected argument 'true'" with usage
   `nullroute run [OPTIONS] -- <ARGV>...`. The last is the one behaviour change: the `--` becomes
   mandatory. The README, `--help` text, every example under `examples/` and `demo/` and every test already
   use `--` (`grep` found no exception; the full suite was run against the scratch copy, see below). Add tests
   asserting 2 for an unknown option after `run` and for a missing `--`.
2. **Listener limit up front.** Count listeners in `main` (ports: one spec per family via
   `forward::port_specs`, plus the proxy's, plus `dns::Plan`'s listeners) and exit 2 before the `--dry-run`
   return when over `MAX_LISTENERS`; keep the check in `forward::prepare` as a backstop but report it as 125
   with a different text. **[unverified]**: written against the code, not compiled; the exact helper
   to expose is `forward::count_listeners(&[Spec])` or a method on the sinkhole plan.
3. **126/127 and the right message.** Tell setup failures from exec failures: in the `pre_exec` closure map
   any `Err(e)` to `io::Error::from_raw_os_error(e.raw_os_error().unwrap_or(libc::EIO) | SETUP_ERROR)` with a
   spare high bit (`1 << 24`). **[verified]** in a 15-line standalone program: std passes the raw value of a
   `pre_exec` error through its error pipe unchanged (`16777218` = `ENOENT | 1<<24` came back from `spawn`), and a
   genuine exec failure comes back as plain `2`. No allocation (`from_raw_os_error` does not box), so it keeps
   the async-signal-safe rule. In `run()`: if the tag is clear and the errno is `ENOENT` → exit 127, `EACCES`/`ENOEXEC`/
   `EISDIR` (and similar) → 126, each with the shell-style message; if the tag is set, mask it off, run
   `explain_spawn_error` (user-namespace hint only here) and exit 125. This fixes inconsistency 5 as a side effect.
   Update `tests/hermetic.rs` (`missing_command_exits_127…`, add a non-executable case), README rows for
   125/126/127 and the Docker analogy sentence. If the spawn is later replaced by our own `clone` + `exec`
   (see [pid-namespace.md](pid-namespace.md), phase 1), the same distinction falls out naturally from the error pipe.
4. **Broken pipe.** In `main`, when `--dry-run` (or `--inspect`) will print, call
   `libc::signal(libc::SIGPIPE, libc::SIG_DFL)` first so a closed reader ends nullroute with the usual signal
   death (141 in a shell), as `ls | head` does, instead of a panic; or write through a helper that ignores
   `EPIPE`. Not applied; the child-process side is unaffected because std restores `SIGPIPE` in children.
5. **README/CHANGELOG/CONTRIBUTING.** Rewrite the exit-code table with the policy above (2 = usage/limits,
   125 = sandbox, 126/127 = command), drop "the command couldn't be started (not found, not executable)"
   from 125, fix the Docker sentence ("125 for the runner, 126 and 127 for the contained command, like
   Docker; usage errors are 2, as for most CLIs"), and add a short "exit codes" paragraph to `CONTRIBUTING.md`
   saying new argument validation returns 2 before any side effect and runtime/setup failures return 125.
6. **Docs for judgment calls:** state in the README that `--hide-socket`/`--allow-socket` paths that don't
   exist are ignored (the first already warns).

## Scratch-copy verification

A copy of `Cargo.toml`, `Cargo.lock`, `src/` and `tests/` in a temp directory (deleted afterwards, not part
of this PR) had the PR A diff and the `last = true` change applied and was built with `cargo build --locked`. The results
quoted above come from it. The full `cargo test --locked` suite then ran against that copy (the PR A diff, the
`last = true` change and the new test below): 214 tests passed, 0 failed, so nothing in the repository relied on the old codes or on the
missing `--`. The sketched `too_many_ports_is_a_usage_error` test passed there too.

## Unverified

- User namespaces refused (125 via `explain_spawn_error`): this host allows them.
- Handover/start failures after spawn.
- The listener-count helper and the 126/127 mapping in nullroute itself (only the std mechanism was run).
- Behaviour of other callers' scripts that rely on 125.
