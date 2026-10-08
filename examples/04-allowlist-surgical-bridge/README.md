# Example 4: Surgical Host Allowlisting with `--allow`

`nullroute` isn't an all-or-nothing blunt instrument. When your integration test or build actually needs access to specific third-party APIs or external resources, `--allow` sets up a surgical allowlist.

## Key Invariants

1. **Bare Sealed Runs vs Allowlist:** In a bare sealed run (`nullroute run -- <cmd>`), loopback is isolated and outbound traffic fails immediately at the socket layer; no breach report is written because no proxy is running.
2. **Proxy and DNS Sinkhole:** When `--allow` is provided, `nullroute` spins up an internal proxy and DNS sinkhole.
3. **Breach Reporting:** Unlisted domains return `403 Forbidden` through the proxy (or fail name resolution through the DNS sinkhole), and `nullroute` captures every blocked attempt in the breach report (`--report-json`).

## Quick Demo

Run the demo script:

```bash
./run.sh
```

Or step-by-step:

### 1. Completely sealed (default, socket error, silent drop):
```bash
nullroute run -- curl http://example.com
```

### 2. Surgical allowlist:
```bash
nullroute run --allow example.com -- curl http://example.com
```

Attempting to reach an unallowed host (`example.org`) will be intercepted and reported:
```bash
nullroute run --allow example.com -- curl http://example.org
```
