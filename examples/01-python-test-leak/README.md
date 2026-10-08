# Example 1: Catching Accidental External Test Leaks

Unit and integration tests often accidentally hit production or external third-party endpoints (analytics, telemetry, remote services). In local dev, this passes silently; in CI, it causes flaky builds or security leaks.

With `nullroute`, you don't need complicated mock configurations or monkeypatching—outbound traffic is blocked at the kernel network namespace boundary.

## What This Example Demonstrates

1. **Unsealed Execution (Default):** Running without isolation allows tests to silently leak out to the real internet (requires online connection to `example.com`).
2. **Sealed Execution (`nullroute run --`):** The process is isolated with a private loopback interface (`lo`). Outbound socket connections fail immediately at the socket layer.
3. **Breach Reporting (`--report-json`):** When `--allow` is used, any attempt to contact unallowed hosts is captured by the internal proxy sinkhole and recorded in the JSON breach report.
4. **Strict CI Enforcement (`--strict`):** If a test or build step attempts unauthorized network requests but swallows the error (exiting 0), `--strict` forces `nullroute` to exit with code `1`, failing the CI build.
5. **Surgical Egress Bridge (`--allow`):** Legitimate external endpoints can be explicitly allowlisted while keeping everything else sealed.

## Quick Demo

Run the demo script:

```bash
./run.sh
```

Or step-by-step:

### 1. Normal run (leaks outbound to example.com; requires internet):
```bash
python3 test_payment.py
```

### 2. Sealed with nullroute (instant socket failure):
```bash
nullroute run -- python3 test_payment.py
```

### 3. Surgical bridge with `--allow`:
```bash
nullroute run --allow example.com -- python3 test_payment.py
```
