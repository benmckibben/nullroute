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
echo " Notice how the test silently reaches out to example.com..."
echo " (Note: This step requires live internet connectivity)"
echo "=================================================================="
if curl -sf --connect-timeout 2 -I http://example.com &>/dev/null; then
    set +e
    python3 test_payment.py
    NORMAL_STATUS=$?
    set -e
    echo "Normal run exit code: $NORMAL_STATUS"
else
    echo "skipping step 1: host is currently offline or example.com is unreachable."
fi

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
echo " STEP 3: Breach Reporting with --report-json and --allow"
echo " When an unallowed host is targeted, nullroute captures the attempt."
echo " We verify the breach report directly from JSON output."
echo "=================================================================="
REPORT_FILE="$(mktemp --suffix=.json)"
set +e
# Allow a benign host (example.org); the test targets example.com
"$NULLROUTE" run --allow example.org --report-json "$REPORT_FILE" -- python3 test_payment.py
set -e

echo "Verifying breach report captures the unallowed destination..."
python3 -c "
import json, sys

with open('$REPORT_FILE') as f:
    report = json.load(f)

blocked = report.get('blocked', [])
targets = [b.get('target') for b in blocked]
print(f'Blocked targets in report: {targets}')

if any('example.com' in t for t in targets):
    print('✔ Verified: example.com was correctly intercepted and recorded.')
else:
    print('✘ Error: example.com not found in breach report!', file=sys.stderr)
    sys.exit(1)
"
rm -f "$REPORT_FILE"

echo ""
echo "=================================================================="
echo " STEP 4: Demonstrating --strict enforcement"
echo " A command that swallows network errors and exits 0 is forced to"
echo " exit 1 by --strict when unauthorized traffic was attempted."
echo "=================================================================="
REPORT_FILE="$(mktemp --suffix=.json)"
set +e
# curl attempts example.com (blocked), but the command pipeline exits 0 (|| true)
"$NULLROUTE" run --strict --allow example.org --report-json "$REPORT_FILE" -- sh -c "curl -s http://example.com || true"
STRICT_EXIT=$?
set -e

STRICT_EXIT="$STRICT_EXIT" REPORT_PATH="$REPORT_FILE" python3 -c '
import json, os, sys

strict_exit = int(os.environ["STRICT_EXIT"])
report_path = os.environ["REPORT_PATH"]

with open(report_path) as f:
    report = json.load(f)

strict_failed = report.get("strict_failed", False)
exit_code = report.get("exit_code", -1)
print(f"Report strict_failed={strict_failed}, reported exit code (after strict)={exit_code}, nullroute status={strict_exit}")

if strict_exit == 1 and strict_failed:
    print("✔ Verified: --strict converted exit 0 into exit 1 due to recorded breach.")
else:
    print("✘ Error: --strict failed to enforce exit 1!", file=sys.stderr)
    sys.exit(1)
'
rm -f "$REPORT_FILE"

echo ""
echo "=================================================================="
echo " STEP 5: Running with surgical --allow example.com"
echo " (Opt-in external test; checks internet connectivity first)"
echo "=================================================================="
if curl -sf --connect-timeout 2 -I http://example.com &>/dev/null; then
    set +e
    "$NULLROUTE" run --allow example.com -- python3 test_payment.py
    ALLOWED_STATUS=$?
    set -e
    if [[ $ALLOWED_STATUS -eq 0 ]]; then
        echo "Allowed run succeeded cleanly!"
    else
        echo "Error: allowed run failed despite online connectivity (exit code: $ALLOWED_STATUS)" >&2; exit $ALLOWED_STATUS
    fi
else
    echo "skipping: offline or external connectivity to example.com unavailable."
fi
