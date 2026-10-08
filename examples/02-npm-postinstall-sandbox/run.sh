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

cd "$SCRIPT_DIR"

echo "=================================================================="
echo " STEP 1: Running untrusted postinstall hook normally (NO nullroute)"
echo " Notice how the script can freely dial out and exfiltrate data..."
echo "=================================================================="
node postinstall.js || true

echo ""
echo "=================================================================="
echo " STEP 2: Running under nullroute sandbox"
echo " Notice: instant network failure, host environment safe."
echo "=================================================================="
"$NULLROUTE" run -- node postinstall.js || true
