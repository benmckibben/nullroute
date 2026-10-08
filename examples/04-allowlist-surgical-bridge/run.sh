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
echo "=================================================================="
set +e
"$NULLROUTE" run -- curl -s --connect-timeout 2 https://api.github.com
GITHUB_BLOCKED=$?
"$NULLROUTE" run -- curl -s --connect-timeout 2 https://api.stripe.com
STRIPE_BLOCKED=$?
set -e

if [[ $GITHUB_BLOCKED -ne 0 && $STRIPE_BLOCKED -ne 0 ]]; then
    echo "-> Egress blocked as expected (non-zero exits)."
else
    echo "-> Error: requests escaped sandbox without --allow!"
    exit 1
fi

echo ""
echo "=================================================================="
echo " STEP 2: Run with --allow api.github.com"
echo " (Opt-in external test; checks internet connectivity first)"
echo "=================================================================="
if curl -s --connect-timeout 2 -I https://api.github.com &>/dev/null; then
    echo "Checking api.github.com (allowed):"
    "$NULLROUTE" run --allow api.github.com -- curl -s -I https://api.github.com | head -n 1
    
    echo "Checking api.stripe.com (not allowed, should report block):"
    set +e
    "$NULLROUTE" run --allow api.github.com -- curl -s --connect-timeout 2 https://api.stripe.com
    STRIPE_STILL_BLOCKED=$?
    set -e
    if [[ $STRIPE_STILL_BLOCKED -ne 0 ]]; then
        echo "-> api.stripe.com remained blocked as expected!"
    fi
else
    echo "skipping step 2: host is currently offline or api.github.com is unreachable."
fi
