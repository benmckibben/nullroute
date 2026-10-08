# Example 2: Sandboxing Untrusted `npm` / Postinstall Scripts

Supply chain attacks and aggressive telemetry often exploit package installation scripts (`postinstall`, `preinstall`) to exfiltrate environment variables, SSH keys, or cloud credentials.

With `nullroute`, untrusted build scripts or package hooks run in a network-sealed sandbox where all external calls fail immediately without leaking host secrets.

## Quick Demo

Run the demo script:

```bash
./run.sh
```

Or step-by-step:

### 1. Normal execution (leaks out to external HTTP endpoint):
```bash
node postinstall.js
```

### 2. Sealed with nullroute (blocked at kernel namespace boundary):
```bash
nullroute run -- node postinstall.js
```
