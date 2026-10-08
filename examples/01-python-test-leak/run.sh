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
echo " STEP 2: Running with nullroute (Sealed run)"
echo " In a bare sealed run (no --allow), loopback is isolated and"
echo " outbound requests fail immediately at the socket layer."
echo "=================================================================="
set +e
"$NULLROUTE" run -- python3 test_payment.py
TEST_STATUS=$?
set -e

if [[ $TEST_STATUS -ne 0 ]]; then
    echo "-> Test failed as expected when external network was sealed! (exit code: $TEST_STATUS)"
else
    echo "-> Unexpected: test succeeded without network!"
    exit 1
fi

echo ""
echo "=================================================================="
echo " STEP 3: Running with --strict and --allow (Demonstrating breach report)"
echo " With --allow and --strict, attempts to reach unauthorized hosts"
echo " are recorded and force nullroute to exit 1."
echo "=================================================================="
REPORT_FILE="$(mktemp --suffix=.json)"
set +e
# Allow a benign host (e.g. example.com), so the test's call to api.github.com
# is captured by the proxy allowlist check and triggers --strict exit 1
"$NULLROUTE" run --strict --allow example.com --report-json "$REPORT_FILE" -- python3 test_payment.py
STRICT_STATUS=$?
set -e

echo "Strict run exit code: $STRICT_STATUS (Expected: 1 from --strict violation)"
if [[ -f "$REPORT_FILE" ]]; then
    echo "Breach report captured:"
    cat "$REPORT_FILE"
    rm -f "$REPORT_FILE"
fi

echo ""
echo "=================================================================="
echo " STEP 4: Running with surgical --allow api.github.com"
echo " (Opt-in external test; checks internet connectivity first)"
echo "=================================================================="
if curl -s --connect-timeout 2 -I https://api.github.com &>/dev/null; then
    "$NULLROUTE" run --allow api.github.com -- python3 test_payment.py
    echo "Allowed run succeeded cleanly!"
else
    echo "skipping: offline or external connectivity to api.github.com unavailable."
fi
