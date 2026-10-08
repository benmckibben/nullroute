#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

source "$REPO_ROOT/examples/common-preflight.sh"
preflight_check
NULLROUTE="$(find_nullroute "$REPO_ROOT")"

PORT=54321

echo "Starting background mock service on host 127.0.0.1:$PORT..."
python3 "$SCRIPT_DIR/mock_db_service.py" "$PORT" &
SERVICE_PID=$!

cleanup() {
    kill "$SERVICE_PID" 2>/dev/null || true
}
trap cleanup EXIT

# Wait briefly for service to bind
sleep 0.5

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
import socket, subprocess, time

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
print('Sandbox process status:', line.strip())

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(1.0)
try:
    s.connect(('127.0.0.1', 43219))
    print('ERROR: Host reached sandbox port!')
except Exception as e:
    print('Host attempt to reach sandbox port refused (expected isolation):', e)
finally:
    s.close()
    proc.terminate()
    proc.wait()
"
