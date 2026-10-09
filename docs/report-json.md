# The `--report-json` file

`nullroute run --report-json FILE -- COMMAND` writes what was blocked as JSON, for CI
artifacts and scripts. This page is the contract for that file. The layout is pinned by golden
files in `tests/golden/`, so a change to it shows up in review.

## When it is written

- On every run that gets as far as running the command, clean or not, and also when the command
  failed or was killed by a signal. A clean run has `"blocked": []` and `"rewritten": []`.
- After the command has exited and `--strict` has been applied, so `exit_code` is the code
  nullroute exits with.
- Not with `--dry-run` (nothing runs), and not when nullroute fails before the command starts
  (exit `2`, `125`, `126`, `127`).
- The path is checked before the command runs: if it cannot be written, nullroute exits `2` and runs
  nothing. If writing fails after the run, nullroute prints an error and a run that would have
  exited `0` exits `74` instead (the file then holds `"exit_code": 0`); a non-zero exit is kept.

## Layout

```json
{
  "schema_version": 1,
  "command": ["python3", "-c", "..."],
  "exit_code": 1,
  "strict_failed": true,
  "blocked": [
    {"kind": "dns", "target": "api.example.test", "reason": "not in --allow", "count": 2}
  ],
  "rewritten": []
}
```

| Field | Type | Meaning |
|---|---|---|
| `schema_version` | integer | Version of this layout (currently `1`). |
| `command` | array of strings | The command and its arguments, as given after `--`. |
| `exit_code` | integer | The exit code nullroute exits with: the command's own code (`128+N` if signal `N` killed it), or `1` if `--strict` turned a success into a failure. |
| `strict_failed` | boolean | `true` only if `--strict` changed the exit code: the command exited `0`, something was blocked, and nullroute exited `1`. |
| `blocked` | array of entries | Everything that was blocked, one entry per `(kind, target)`. |
| `rewritten` | array of entries | Requests `--seal-docker` changed and let through. Not blocks; `--strict` ignores them. |

Each entry is an object:

| Field | Type | Meaning |
|---|---|---|
| `kind` | string | `socket`, `proxy`, `docker` or `dns` in `blocked`; `rewritten` in `rewritten`. |
| `target` | string | What was attempted (see below). |
| `reason` | string | Why, in words. For people: don't match on it. |
| `count` | integer | How many attempts (connections, requests or DNS queries) there were, at least 1. |

`target` by kind:

| Kind | `target` is |
|---|---|
| `socket` | the path of the hidden Unix socket |
| `proxy` | `host:port` the `--allow` proxy refused: the request's host, or, when the `Host` header or the TLS server name named another host, that name |
| `dns` | the name that was looked up and refused, or `host:port` for a relayed connection the sinkhole refused |
| `docker` | the Docker API route that was refused, e.g. `networks/connect` |
| `rewritten` | the Docker API route that was changed, e.g. `containers/create` |

Entries are sorted by kind (`socket`, `proxy`, `docker`, `dns`), then by target.
Strings are UTF-8 with the JSON escapes `\"`, `\\`, `\n` and `\u00XX` for other control characters.

## Reading the exit code

A command can exit `1` itself, so `1` alone does not say who decided. The file does:

| `exit_code` | `strict_failed` | Meaning |
|---|---|---|
| `0` | `false` | The command succeeded and (with `--strict`) nothing was blocked. |
| `1` | `true` | The command succeeded, but `--strict` found blocked attempts. Look at `blocked`. |
| `1` | `false` | The command itself exited `1`. |
| anything else | `false` | The command's own code. nullroute's other codes (`2`, `74`, `125`, `126`, `127`) mean nullroute did not run it or could not write the report; see the README's exit-code table. |

The `blocked` list can be non-empty with `strict_failed: false`: without `--strict`, or when the
command failed anyway, blocked attempts are recorded but do not change the exit code.

## Compatibility

- `schema_version` goes up only for a change that can break a consumer: removing or renaming a
  field, or changing what one means. Adding a field, or a new `kind`, does not.
- Read the fields you need and ignore the rest. Treat an unknown `kind` as a block unless it is
  in `rewritten`.

## Not in the file

A direct connection to an IP address fails inside the kernel (`ENETUNREACH`) and never reaches
nullroute, so it is neither listed nor counted by `--strict`.
