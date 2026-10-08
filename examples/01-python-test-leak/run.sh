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
echo " STEP 1: Running python test normally (NO nullroute)"
echo " Notice how the test silently reaches out to GitHub API..."
echo "=================================================================="
python3 test_payment.py || true

echo ""
echo "=================================================================="
echo " STEP 2: Running with nullroute (Outbound sealed off!)"
echo " Notice: instant drop, no network leak, exit code passed to CI."
echo "=================================================================="
"$NULLROUTE" run -- python3 test_payment.py || true

echo ""
echo "=================================================================="
echo " STEP 3: Running with surgical --allow api.github.com"
echo " Only explicitly allowed host can be reached."
echo "=================================================================="
"$NULLROUTE" run --allow api.github.com -- python3 test_payment.py
