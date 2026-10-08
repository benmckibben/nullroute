#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

source "$REPO_ROOT/examples/common-preflight.sh"
preflight_check
NULLROUTE="$(find_nullroute "$REPO_ROOT")"

cd "$SCRIPT_DIR"

echo "=================================================================="
echo " STEP 1: Attempt to curl without --allow"
echo " Requests are completely blocked at the sandbox boundary."
echo " (Bare sealed runs drop traffic silently; no breach report is written)"
echo "=================================================================="
set +e
"$NULLROUTE" run -- curl -s --connect-timeout 2 http://example.com
EXAMPLE_BLOCKED=$?
"$NULLROUTE" run -- curl -s --connect-timeout 2 http://example.org
ORG_BLOCKED=$?
set -e

if [[ $EXAMPLE_BLOCKED -ne 0 && $ORG_BLOCKED -ne 0 ]]; then
    echo "-> Egress blocked as expected (non-zero exits)."
else
    echo "-> Error: requests escaped sandbox without --allow!" >&2
    exit 1
fi

echo ""
echo "=================================================================="
echo " STEP 2: Run with --allow example.com"
echo " (Opt-in external test; checks internet connectivity first)"
echo "=================================================================="
if curl -sf --connect-timeout 2 -I http://example.com &>/dev/null; then
    echo "Checking example.com (allowed):"
    set +e
    "$NULLROUTE" run --allow example.com -- curl -s -f -o /dev/null -w "%{http_code}\n" http://example.com
    ALLOWED_RC=$?
    set -e
    if [[ $ALLOWED_RC -ne 0 ]]; then
        echo "Error: allowed call to example.com failed (exit code: $ALLOWED_RC)" >&2
        exit 1
    fi
    echo "-> example.com reached successfully."
    
    echo "Checking example.org (not allowed, should return 403 Forbidden via proxy):"
    REPORT_FILE="$(mktemp --suffix=.json)"
    set +e
    # curl -f fails on HTTP 403 status code returned by nullroute proxy
    "$NULLROUTE" run --allow example.com --report-json "$REPORT_FILE" -- curl -sf --connect-timeout 2 http://example.org
    UNALLOWED_RC=$?
    set -e
    
    if [[ $UNALLOWED_RC -ne 0 ]]; then
        echo "-> example.org received 403 Forbidden and was blocked as expected!"
    else
        echo "Error: unallowed host example.org was not blocked by proxy!" >&2
        rm -f "$REPORT_FILE"
        exit 1
    fi

    # Verify breach report records the unallowed destination
    REPORT_PATH="$REPORT_FILE" python3 -c '
import json, os, sys

report_path = os.environ["REPORT_PATH"]
with open(report_path) as f:
    report = json.load(f)

blocked = report.get("blocked", [])
targets = [b.get("target") for b in blocked]
print(f"Blocked targets in report: {targets}")

if any("example.org" in t for t in targets):
    print("✔ Verified: example.org was correctly recorded in the breach report.")
else:
    print("✘ Error: example.org was not recorded in breach report!", file=sys.stderr)
    sys.exit(1)
'
    rm -f "$REPORT_FILE"
else
    echo "skipping step 2: host is currently offline or example.com is unreachable."
fi
