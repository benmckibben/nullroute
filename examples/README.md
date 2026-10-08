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
