#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

source "$REPO_ROOT/examples/common-preflight.sh"
preflight_check
NULLROUTE="$(find_nullroute "$REPO_ROOT")"

cd "$SCRIPT_DIR"

echo "=================================================================="
echo " STEP 1: Running python test normally (NO nullroute)"
echo " Notice how the test silently reaches out to GitHub API..."
echo "=================================================================="
set +e
python3 test_payment.py
NORMAL_STATUS=$?
set -e
echo "Normal run exit code: $NORMAL_STATUS"

echo ""
echo "=================================================================="
echo " STEP 2: Running with nullroute and --strict"
echo " Network sealed off. --strict enforces exit 1 if anything is blocked."
echo "=================================================================="
REPORT_FILE="$(mktemp --suffix=.json)"
set +e
"$NULLROUTE" run --strict --report-json "$REPORT_FILE" -- python3 test_payment.py
NULLROUTE_STATUS=$?
set -e

echo "nullroute run exit code: $NULLROUTE_STATUS (Expected: failure / exit 1 under strict)"
if [[ -f "$REPORT_FILE" ]]; then
    echo "Breach report summary:"
    cat "$REPORT_FILE"
    rm -f "$REPORT_FILE"
fi

echo ""
echo "=================================================================="
echo " STEP 3: Running with surgical --allow api.github.com"
echo " (Opt-in external test; checks internet connectivity first)"
echo "=================================================================="
if curl -s --connect-timeout 2 -I https://api.github.com &>/dev/null; then
    "$NULLROUTE" run --allow api.github.com -- python3 test_payment.py
    echo "Allowed run succeeded cleanly!"
else
    echo "skipping: offline or external connectivity to api.github.com unavailable."
fi
