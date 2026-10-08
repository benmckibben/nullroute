# nullroute Developer Examples

Turnkey examples demonstrating `nullroute`'s zero-leak isolation, surgical bridging, and sandboxing capabilities.

Each example is self-contained and runnable with `./run.sh` in under 5 seconds.

| Example | Focus | Command |
|---|---|---|
| [01-python-test-leak](./01-python-test-leak/) | Catch accidental outbound API calls in test suites | `cd 01-python-test-leak && ./run.sh` |
| [02-npm-postinstall-sandbox](./02-npm-postinstall-sandbox/) | Sandbox untrusted package scripts and prevent exfiltration | `cd 02-npm-postinstall-sandbox && ./run.sh` |
| [03-local-service-port](./03-local-service-port/) | Bridge host databases and local containers using `--port` | `cd 03-local-service-port && ./run.sh` |
| [04-allowlist-surgical-bridge](./04-allowlist-surgical-bridge/) | Surgical egress allowlisting with `--allow` and block reporting | `cd 04-allowlist-surgical-bridge && ./run.sh` |

---

### Running All Examples

You can run each example directory's `run.sh` directly:

```bash
for d in examples/*/; do
    echo "Running $d..."
    (cd "$d" && ./run.sh)
done
```

### Continuous integration

CI (the `examples` job in [`.github/workflows/ci.yml`](../.github/workflows/ci.yml)) builds nullroute and runs examples **01** and **03**, plus `shellcheck` over all example and demo scripts. It runs them with `NULLROUTE_EXAMPLES_OFFLINE=1`, so nothing depends on the public internet:

- `NULLROUTE_EXAMPLES_OFFLINE=1` makes every step that needs live connectivity (calls to example.com / example.org, `curl` connectivity probes) print `skipping ...: ... (offline mode, NOT VERIFIED)` and carry on. Everything that does not need upstream (sealed runs, `--report-json`, `--strict`, `--port`, sinkhole/proxy denials) still runs and asserts. Unset (the default) the scripts behave as before and use the internet when it is reachable.
- Each of 01, 03 (and 02, 04) ends with a summary line, e.g. `examples: 01-python-test-leak: 3 assertions run, 2 skipped (offline mode)`. CI greps for the exact line, so an assertion that gets skipped by accident fails the job instead of passing silently. Expected: 01 runs 3 assertions and skips 2 (steps 1 and 5); 03 runs 4 and skips 0. If you add or remove an assertion, update the counts in the workflow.
- 02 (needs Node, and its only offline-safe check is a sealed run) and 04 (almost entirely about live allowed hosts) are not part of the CI job; run them locally.

To reproduce the CI run locally (after `cargo build`):

```bash
NULLROUTE_EXAMPLES_OFFLINE=1 ./examples/01-python-test-leak/run.sh
NULLROUTE_EXAMPLES_OFFLINE=1 ./examples/03-local-service-port/run.sh
shellcheck -x -P SCRIPTDIR examples/*.sh examples/*/run.sh demo/*.sh
```

### Terminal demo

The animated demo is recorded by [VHS](https://github.com/charmbracelet/vhs) from `demo/nullroute-demo.tape`; run `vhs demo/nullroute-demo.tape` from the repository root (see [`demo/README.md`](../demo/README.md)). `demo/run-demo.sh` plays the same story live without VHS.
