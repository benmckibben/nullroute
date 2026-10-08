#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

NULLROUTE=""
if [[ -x "$REPO_ROOT/target/debug/nullroute" ]]; then
    NULLROUTE="$REPO_ROOT/target/debug/nullroute"
elif [[ -x "$REPO_ROOT/target/release/nullroute" ]]; then
    NULLROUTE="$REPO_ROOT/target/release/nullroute"
elif command -v nullroute &>/dev/null; then
    NULLROUTE="nullroute"
else
    echo "nullroute binary not found! Run 'cargo build' in $REPO_ROOT first." >&2
    exit 1
fi

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
echo " STEP 1: Verify host can reach mock service directly"
echo "=================================================================="
curl -s http://127.0.0.1:$PORT

echo ""
echo "=================================================================="
echo " STEP 2: Run under nullroute WITHOUT --port"
echo " In a fresh network namespace, host 127.0.0.1:$PORT is invisible!"
echo "=================================================================="
"$NULLROUTE" run -- curl -s --connect-timeout 2 http://127.0.0.1:$PORT || echo "-> Connection failed as expected! (Network unreachable or connection refused)"

echo ""
echo "=================================================================="
echo " STEP 3: Run under nullroute WITH --port $PORT"
echo " The host port is surgically bridged into the sandbox loopback!"
echo "=================================================================="
"$NULLROUTE" run --port "$PORT" -- curl -s http://127.0.0.1:$PORT
