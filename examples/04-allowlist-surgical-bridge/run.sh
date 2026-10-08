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
echo " STEP 1: Attempt to curl Stripe and GitHub without --allow"
echo " Both requests are completely blocked at the sandbox boundary."
echo "=================================================================="
"$NULLROUTE" run -- curl -s --connect-timeout 2 https://api.github.com || echo "-> api.github.com blocked as expected!"
"$NULLROUTE" run -- curl -s --connect-timeout 2 https://api.stripe.com || echo "-> api.stripe.com blocked as expected!"

echo ""
echo "=================================================================="
echo " STEP 2: Run with --allow api.github.com"
echo " GitHub succeeds via proxy/sinkhole, Stripe remains blocked!"
echo "=================================================================="
echo "Checking api.github.com (allowed):"
"$NULLROUTE" run --allow api.github.com -- curl -s -I https://api.github.com | head -n 1
echo "Checking api.stripe.com (not allowed):"
"$NULLROUTE" run --allow api.github.com -- curl -s --connect-timeout 2 https://api.stripe.com || echo "-> api.stripe.com still blocked!"
