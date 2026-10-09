# Exit codes

Status: **implemented**. One small item is still open (see [Open](#open)). The user-facing
table is in the [README](../../README.md#what-got-blocked-the-report-and---strict); this note records the
policy, why it is the way it is, and what was checked.

Evidence tags: **[verified]** = run on the current code (the commands are in the table);
**[reasoned]** = from reading the code, not run.

## Policy

| Code | Meaning |
|---|---|
| 0 | the command succeeded (and `--strict` found nothing blocked), or `--dry-run`/`--help`/`--version` succeeded |
| 1 | `--strict`: the command succeeded but something was blocked |
| **2** | **usage error: the command line is invalid, decided from the arguments alone, before anything runs.** Unknown or invalid options, a missing command, values that cannot work, conflicting options, argument limits, an unwritable `--report-json` path |
| 74 | the `--report-json` file could not be written after a run that would have exited 0 |
| **125** | **nullroute could not set up or launch the sandbox for a reason outside the arguments**: user namespaces refused, temp dir or socket creation failed, handover failed |
| 126 | the command exists but could not be executed |
| 127 | the command was not found |
| 128+N | the command was killed by signal N |
| other | the command's own exit code |

Rule of thumb for contributors: *would the same arguments work on a host where namespaces work?* If not,
it is 2; if the arguments are fine and this host or run failed, it is 125.

Why these choices:

- 2 for usage errors is what clap and most CLIs use. 125/126/127 follow Docker: 125 = the runner failed,
  126/127 = the contained command could not be invoked / found. **[verified]** against a local Docker
  daemon: `docker run --network none alpine /nonexistent` exits 127, `... /etc/passwd` 126,
  `docker run --bogus-flag ...` 125. nullroute differs from Docker only in sending usage errors to 2.
- Separating 126/127 from 125 lets a CI script tell "I typo'd the command" from "the sandbox is broken".
  The codes are shared with commands that exit with them themselves, but a script could not tell "125 from
  the command" from "125 from nullroute" anyway; `--report-json` plus the message on stderr tell them apart.
- A `1` is either the command's or `--strict`'s: `strict_failed` in the [JSON report](../report-json.md)
  disambiguates. 74 only ever replaces a would-be 0, so a failing command keeps its own code.

## What the current code does

All codes are produced in `src/main.rs` (`main`, `run`) or by clap before `main`'s body;
`src/lifecycle.rs` has one `_exit(128 + SIGKILL)` in a forked child that nobody observes.

| Code | Run | Result **[verified]** |
|---|---|---|
| 0 | `run -- true`; `run --port 1,...,64 -- true` | 0 |
| 1 | `run --strict -- python3 -c "...getaddrinfo(...) swallowed..."` | 1, `blocked DNS lookup of a.test` |
| 2 | `nullroute`; `run`; `run --port 0 -- true`; `run --port 70000 -- true` | 2 (clap) |
| 2 | `run --port 1,...,65 -- true` | 2, `at most 64 --port values (got 65)` (also with `--dry-run`) |
| 2 | `run --bogus -- true`; `run --strict true` (no `--`) | 2, `unexpected argument` |
| 2 | `run --allow localhost -- true`; `run --resolve foo:1.2.3.4 -- true`; `run --seal-docker-pulls none -- true`; `run --allow x.example --port 53 -- true`; `run --report-json /nonexistent/x.json -- true` | 2, each with its own message |
| 74 | `run --report-json /dev/full -- true` | 74, `writing the report failed` |
| 125 | `TMPDIR=/nonexistent run -- true` | 125, `preparing socket hiding: No such file or directory` |
| 125 | one `--allow` host with 1,101 ports (`--allow x.example:2000 --allow x.example:2001 ...`), with or without `--dry-run` | 125, `could not set up the sandbox: too many listeners (1105 > 1024)` |
| 126 | `run -- /etc/passwd` | 126, `failed to run "/etc/passwd": Permission denied` (no namespace hint) |
| 127 | `run -- /nonexistent/cmd` | 127, `failed to run "/nonexistent/cmd": No such file or directory` |
| 128+N | `run -- sh -c 'kill -TERM $$'` / `kill -INT $$` | 143 / 130 |
| own | `run -- sh -c 'exit 3'` | 3 |
| SIGPIPE | `run --port 1,...,64 --dry-run -- true \| head -1` | the writer dies of SIGPIPE (141 in the shell), no panic |

nullroute itself produces 126 and 127 only for a command that cannot be started; setup failures are 125.

## Open

1. **`--hide-socket /typo`** prints `no such file, ignoring` and exits 0 (`--allow-socket /typo` is silent), so a
   mistyped path leaves the socket reachable. **[verified]** Ignoring missing paths is deliberate for the default
   list (most of those sockets do not exist on most machines); for an explicit flag, exit 2 or a `--strict`
   failure would be safer. Undecided.
