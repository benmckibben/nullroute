# Example 4: Surgical Host Allowlisting with `--allow`

`nullroute` isn't an all-or-nothing blunt instrument. When your integration test or build actually needs access to specific third-party APIs (e.g., GitHub, Stripe), `--allow` sets up a surgical allowlist.

Unlisted domains return `403 Forbidden` through the proxy (or fail name resolution through the DNS sinkhole), and `nullroute` prints a clear summary of blocked destinations.

## Quick Demo

Run the demo script:

```bash
./run.sh
```

Or step-by-step:

### 1. Completely sealed (default):
```bash
nullroute run -- curl https://api.github.com
```

### 2. Surgical allowlist:
```bash
nullroute run --allow api.github.com -- curl https://api.github.com
```
Attempting to reach an unallowed host (`api.stripe.com`) will be blocked and reported:
```bash
nullroute run --allow api.github.com -- curl https://api.stripe.com
```
