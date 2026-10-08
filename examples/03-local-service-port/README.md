# Example 3: Bridging Local Databases and Services with `--port`

When you isolate a process with `nullroute`, it gets a private loopback interface. A database or Redis instance listening on the host's `127.0.0.1:5432` is invisible inside the sandbox by default.

Rather than punching a hole in the entire network or writing custom mocks, `--port <PORT>` surgically bridges the specific host port into the sandbox loopback.

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

### 2. Sealed run without `--port` (connection fails):
```bash
nullroute run -- curl http://127.0.0.1:54321
```

### 3. Bridged run with `--port 54321` (transparently reaches host service):
```bash
nullroute run --port 54321 -- curl http://127.0.0.1:54321
```
