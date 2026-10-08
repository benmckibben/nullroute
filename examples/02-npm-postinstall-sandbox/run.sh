#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

source "$REPO_ROOT/examples/common-preflight.sh"
preflight_check
NULLROUTE="$(find_nullroute "$REPO_ROOT")"

cd "$SCRIPT_DIR"

# DEFENSE-IN-DEPTH: Run with a disposable temporary HOME and unset SSH_AUTH_SOCK.
# Note: Network namespaces isolate TCP/UDP/DNS, NOT filesystem or host Unix domain sockets.
# Unsetting SSH_AUTH_SOCK via `env -u` drops the environment pointer;
# for true protection against hostile code accessing existing sockets, use `--hide-socket`.
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
echo " STEP 2: Running under nullroute sandbox (Network drop)"
echo " Notice: instant network drop. Egress blocked at socket layer."
echo "=================================================================="
set +e
HOME="$DEMO_TMP_HOME" env -u SSH_AUTH_SOCK "$NULLROUTE" run -- node postinstall.js
STATUS=$?
set -e

if [[ $STATUS -ne 0 ]]; then
    echo "-> Exfiltration attempt was successfully blocked! Node exit code: $STATUS"
else
    echo "-> Unexpected: process exited 0 under nullroute."
    exit 1
fi
