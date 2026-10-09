#!/usr/bin/env bash
# nullroute: Interactive CLI Terminal Demo Runner
# Simulates the live terminal experience for asciinema or live presentations.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

NULLROUTE=""
if [[ -x "$REPO_ROOT/target/debug/nullroute" ]]; then
    NULLROUTE="$REPO_ROOT/target/debug/nullroute"
elif [[ -x "$REPO_ROOT/target/release/nullroute" ]]; then
    NULLROUTE="$REPO_ROOT/target/release/nullroute"
elif command -v nullroute &>/dev/null; then
    NULLROUTE="nullroute"
else
    echo "nullroute binary not found! Run 'cargo build' in $REPO_ROOT first." >&2
    exit 125
fi

type_cmd() {
    local cmd="$1"
    echo -ne "\033[1;32m$\033[0m \033[1;37m"
    for (( i=0; i<${#cmd}; i++ )); do
        echo -n "${cmd:$i:1}"
        sleep 0.015
    done
    echo -e "\033[0m"
    sleep 0.2
}

clear 2>/dev/null || true

echo -e "\033[1;34m=== nullroute: terminal demo ===\033[0m\n"
sleep 0.5

echo -e "\033[1;33m[Scene 1] Running test suite without isolation (external API leak):\033[0m"
type_cmd "python3 examples/01-python-test-leak/test_payment.py"
python3 "$REPO_ROOT/examples/01-python-test-leak/test_payment.py" || true
echo ""
sleep 1

echo -e "\033[1;33m[Scene 2] Running sealed under nullroute (zero code changes, instant drop):\033[0m"
type_cmd "nullroute run -- python3 examples/01-python-test-leak/test_payment.py"
"$NULLROUTE" run -- python3 "$REPO_ROOT/examples/01-python-test-leak/test_payment.py" || true
echo ""
sleep 1

echo -e "\033[1;33m[Scene 3] Surgical egress allowlisting (--allow example.com):\033[0m"
type_cmd "nullroute run --allow example.com -- python3 examples/01-python-test-leak/test_payment.py"
if curl -sf --connect-timeout 2 -I http://example.com &>/dev/null; then
    "$NULLROUTE" run --allow example.com -- python3 "$REPO_ROOT/examples/01-python-test-leak/test_payment.py" || true
else
    echo "skipping live network call: host is currently offline."
fi
echo ""
sleep 1

echo -e "\033[1;33m[Scene 4] Inspecting sandbox topology and bridged boundaries:\033[0m"
type_cmd "nullroute run --allow example.com --port 5432 --inspect --dry-run -- true"
"$NULLROUTE" run --allow example.com --port 5432 --inspect --dry-run -- true
echo ""
echo -e "\033[1;32m✔ Demo complete.\033[0m"
