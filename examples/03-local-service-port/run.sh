#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

source "$REPO_ROOT/examples/common-preflight.sh"
preflight_check
NULLROUTE="$(find_nullroute "$REPO_ROOT")"

# 1. Dynamically find a free port to avoid race conditions and collisions
PORT=$(python3 -c 'import socket; s = socket.socket(); s.bind(("", 0)); print(s.getsockname()[1]); s.close()')

echo "Starting background mock service on host 127.0.0.1:$PORT..."
python3 "$SCRIPT_DIR/mock_db_service.py" "$PORT" &
SERVICE_PID=$!

cleanup() {
    kill "$SERVICE_PID" 2>/dev/null || true
}
trap cleanup EXIT

# 2. Poll until the service is actively accepting connections instead of arbitrary sleep
READY=0
for _ in {1..50}; do
    if curl -s "http://127.0.0.1:$PORT" &>/dev/null; then
        READY=1
        break
    fi
    sleep 0.05
done

if [[ $READY -ne 1 ]]; then
    echo "Error: mock service failed to start on port $PORT" >&2
    exit 125
fi

echo ""
echo "=================================================================="
echo " STEP 1: Host reaches service directly"
echo "=================================================================="
curl -s "http://127.0.0.1:$PORT"

echo ""
echo "=================================================================="
echo " STEP 2: Sealed under nullroute WITHOUT --port"
echo " Private sandbox loopback: host 127.0.0.1:$PORT is completely invisible."
echo "=================================================================="
set +e
"$NULLROUTE" run -- curl -s --connect-timeout 2 "http://127.0.0.1:$PORT"
SEALED_STATUS=$?
set -e
if [[ $SEALED_STATUS -ne 0 ]]; then
    echo "-> Sealed call failed as expected! (Exit code: $SEALED_STATUS)"
else
    echo "-> Unexpected success without --port!"
    exit 1
fi

echo ""
echo "=================================================================="
echo " STEP 3: Bridged with --port $PORT"
echo " Host service is surgically bridged into the sandbox's localhost."
echo "=================================================================="
"$NULLROUTE" run --port "$PORT" -- curl -s "http://127.0.0.1:$PORT"

echo ""
echo "=================================================================="
echo " STEP 4: Demonstrating bidirectional isolation"
echo " A server listening INSIDE the sandbox cannot be reached from host!"
echo "=================================================================="
python3 -c "
import socket, subprocess, sys, time

inner_code = '''
import socket, time
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind(('127.0.0.1', 43219))
s.listen(1)
print('SANDBOX_LISTENING', flush=True)
time.sleep(3)
'''

proc = subprocess.Popen(
    ['$NULLROUTE', 'run', '--', 'python3', '-c', inner_code],
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    text=True
)

line = proc.stdout.readline()
if 'SANDBOX_LISTENING' not in line:
    print('Error: sandbox server failed to start:', line.strip(), file=sys.stderr)
    proc.terminate()
    sys.exit(1)

print('Sandbox process status:', line.strip())

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(1.0)
try:
    s.connect(('127.0.0.1', 43219))
    print('ERROR: Host reached sandbox port!', file=sys.stderr)
    s.close()
    proc.terminate()
    proc.wait()
    sys.exit(1)
except Exception as e:
    print('Host attempt to reach sandbox port refused (expected isolation):', e)
finally:
    s.close()
    proc.terminate()
    proc.wait()
"
