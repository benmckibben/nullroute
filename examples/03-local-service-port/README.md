# Example 3: Bridging Local Databases and Services with `--port`

When you isolate a process with `nullroute`, it gets a private loopback interface (`lo`). A database or Redis instance listening on the host's `127.0.0.1:5432` is invisible inside the sandbox by default.

Rather than punching a hole in the entire network or writing custom mocks, `--port <PORT>` surgically bridges the specific host port into the sandbox loopback.

## Key Invariants

1. **Host to Sandbox Bridging:** `--port 54321` transparently forwards traffic sent to `localhost:54321` inside the sandbox to the host's `localhost:54321`.
2. **Bidirectional Loopback Isolation:** The bridge is strictly one-way for the designated ports. A server process started *inside* the sandbox is completely unreachable from the host machine.
3. **Background Process Cleanup:** When the sandboxed command exits, `nullroute` automatically terminates any background child processes started inside the sandbox.

## Quick Demo

Run the demo script:

```bash
./run.sh
```

Or step-by-step:

### 1. Start a local service on host port 54321:
```bash
python3 mock_db_service.py 54321 &
```

### 2. Sealed run without `--port` (connection refused / unreachable):
```bash
nullroute run -- curl http://127.0.0.1:54321
```

### 3. Bridged run with `--port 54321` (transparently reaches host service):
```bash
nullroute run --port 54321 -- curl http://127.0.0.1:54321
```
