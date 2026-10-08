# Example 2: Sandboxing Untrusted `npm` / Postinstall Scripts

Supply chain attacks and aggressive telemetry often exploit package installation scripts (`postinstall`, `preinstall`) to exfiltrate environment variables, SSH keys, or cloud credentials.

With `nullroute`, untrusted build scripts or package hooks run in a network-sealed sandbox where all external calls fail immediately without leaking host secrets.

## ⚠️ Security Boundaries & Defense-in-Depth

It is crucial to understand `nullroute`'s exact boundary:
1. **Network Layer Sealed:** `nullroute` creates a network namespace with only a private loopback interface (`lo`). Outbound TCP/UDP packets and DNS lookups are blocked.
2. **Local Unix Sockets & Files:** Network namespaces **do not** isolate the filesystem or non-abstract Unix domain sockets by path. 
   - Standard Docker sockets and system D-Bus are hidden by default via mount namespace redirection to decoy sockets.
   - User agent sockets like `SSH_AUTH_SOCK`, X11, or GPG agent **remain reachable** unless explicitly hidden (`--hide-socket "$SSH_AUTH_SOCK"`) or unset.
3. **Recommended Practice:** Always run untrusted scripts with a clean/temporary `HOME` (`MOCK_HOME=$(mktemp -d)`), stripped credentials, and unset `SSH_AUTH_SOCK` in addition to `nullroute run --`.

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
SSH_AUTH_SOCK="" nullroute run --strict -- node postinstall.js
```
