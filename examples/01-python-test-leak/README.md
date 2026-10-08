# Example 1: Catching Accidental External Test Leaks

Unit and integration tests often accidentally hit production or external third-party APIs (Stripe, GitHub, analytics, telemetry). In local dev, this passes silently; in CI, it causes flaky builds or security leaks.

With `nullroute`, you don't need complicated mock configurations or monkeypatching—outbound traffic is blocked at the kernel network namespace boundary.

## Quick Demo

Run the demo script:

```bash
./run.sh
```

Or run step-by-step:

### 1. Normal run (leaks outbound to GitHub API):
```bash
python3 test_payment.py
```

### 2. Sealed with nullroute (instant network block, exit code preserved):
```bash
nullroute run -- python3 test_payment.py
```

### 3. Surgical bridge with `--allow`:
```bash
nullroute run --allow api.github.com -- python3 test_payment.py
```
