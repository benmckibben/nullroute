#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

source "$REPO_ROOT/examples/common-preflight.sh"
preflight_check
NULLROUTE="$(find_nullroute "$REPO_ROOT")"

cd "$SCRIPT_DIR"

# DEFENSE-IN-DEPTH: Run with a disposable temporary HOME and unset SSH_AUTH_SOCK
# nullroute seals the NETWORK namespace, but Unix domain sockets like SSH_AUTH_SOCK
# and host files are NOT isolated by network namespaces alone.
DEMO_TMP_HOME="$(mktemp -d)"
cleanup() {
    if [[ -n "${DEMO_TMP_HOME:-}" && -d "$DEMO_TMP_HOME" ]]; then
        rm -rf "$DEMO_TMP_HOME"
    fi
}
trap cleanup EXIT

echo "=================================================================="
echo " STEP 1: Running postinstall hook directly (leaks to example.com)"
echo "=================================================================="
if curl -s --connect-timeout 2 -I https://example.com &>/dev/null; then
    set +e
    HOME="$DEMO_TMP_HOME" node postinstall.js
    set -e
else
    echo "skipping step 1: host is currently offline."
fi

echo ""
echo "=================================================================="
echo " STEP 2: Running under nullroute sandbox with --strict"
echo " Notice: instant network drop. Egress blocked."
echo " Note: We explicitly unset SSH_AUTH_SOCK or pass --hide-socket"
echo " to ensure local agent sockets are guarded."
echo "=================================================================="
set +e
HOME="$DEMO_TMP_HOME" SSH_AUTH_SOCK="" "$NULLROUTE" run --strict -- node postinstall.js
STATUS=$?
set -e

if [[ $STATUS -ne 0 ]]; then
    echo "-> Exfiltration attempt was successfully blocked! Exit code: $STATUS"
else
    echo "-> Unexpected: process exited 0 under nullroute."
    exit 1
fi
