#!/usr/bin/env bash
# Common preflight checks and helpers for nullroute examples.
#
# Offline mode: set NULLROUTE_EXAMPLES_OFFLINE=1 to skip the steps that need the
# public internet (calls to example.com / example.org and the curl connectivity
# probes). Every skip is announced loudly and counted. All steps that do not
# need upstream connectivity (sealed runs, --report-json, --strict, --port, ...)
# still run and assert. Scripts that use the helpers below end with a summary:
#
#   examples: <name>: N assertions run, M skipped (<mode>)
#
# so CI can check that the expected assertions really ran, not just that the
# script exited 0. The default (unset) behaviour is unchanged.

EXAMPLES_ASSERTIONS=0
EXAMPLES_SKIPPED=0

# True when NULLROUTE_EXAMPLES_OFFLINE=1.
examples_offline() {
    [[ "${NULLROUTE_EXAMPLES_OFFLINE:-}" == "1" ]]
}

# Call right after an assertion has passed (a failing assertion exits the script).
assertion_passed() {
    EXAMPLES_ASSERTIONS=$((EXAMPLES_ASSERTIONS + 1))
}

# skip_step <step> <reason>: announce and count a skipped step.
skip_step() {
    EXAMPLES_SKIPPED=$((EXAMPLES_SKIPPED + 1))
    if examples_offline; then
        echo "skipping $1: $2 (offline mode, NOT VERIFIED)"
    else
        echo "skipping $1: $2"
    fi
}

# examples_summary <name>: print the assertion-count line (call last, on success).
examples_summary() {
    local mode="online"
    if examples_offline; then
        mode="offline mode"
    elif [[ $EXAMPLES_SKIPPED -gt 0 ]]; then
        mode="upstream unreachable"
    fi
    echo "examples: $1: $EXAMPLES_ASSERTIONS assertions run, $EXAMPLES_SKIPPED skipped ($mode)"
}

preflight_check() {
    # 1. OS Check: Linux only
    if [[ "$(uname -s)" != "Linux" ]]; then
        echo "Error: nullroute requires Linux (network namespaces and unshare). Current OS: $(uname -s)" >&2
        exit 125
    fi

    # 2. Root check: should not run as root/sudo
    if [[ "$(id -u)" -eq 0 ]]; then
        echo "Warning: nullroute is designed for unprivileged users. Running as root allows bypassing socket decoys." >&2
    fi

    # 3. User namespace sysctl checks
    if [[ -f /proc/sys/kernel/apparmor_restrict_unprivileged_userns ]] && \
       [[ "$(< /proc/sys/kernel/apparmor_restrict_unprivileged_userns)" -eq 1 ]]; then
        echo "Error: unprivileged user namespaces are restricted by AppArmor." >&2
        echo "Note: Disabling this relaxes system-wide containment (sysctl -w kernel.apparmor_restrict_unprivileged_userns=0)." >&2
        exit 125
    fi

    if [[ -f /proc/sys/kernel/unprivileged_userns_clone ]] && \
       [[ "$(< /proc/sys/kernel/unprivileged_userns_clone)" -eq 0 ]]; then
        echo "Error: unprivileged user namespaces are disabled (unprivileged_userns_clone=0)." >&2
        exit 125
    fi

    if [[ -f /proc/sys/user/max_user_namespaces ]] && \
       [[ "$(< /proc/sys/user/max_user_namespaces)" -eq 0 ]]; then
        echo "Error: max_user_namespaces is 0." >&2
        exit 125
    fi

    # 4. Runtime functional probe (covers Docker seccomp profiles, container limits)
    if command -v unshare &>/dev/null; then
        if ! unshare --user --net --map-current-user true 2>/dev/null; then
            echo "Error: unshare probe failed (unprivileged user+net namespaces blocked by container seccomp or security policy)." >&2
            exit 125
        fi
    fi
}

find_nullroute() {
    local repo_root="$1"
    if [[ -x "$repo_root/target/debug/nullroute" ]]; then
        echo "$repo_root/target/debug/nullroute"
    elif [[ -x "$repo_root/target/release/nullroute" ]]; then
        echo "$repo_root/target/release/nullroute"
    elif command -v nullroute &>/dev/null; then
        command -v nullroute
    else
        echo "Error: nullroute binary not found. Build it with 'cargo build' in $repo_root first." >&2
        exit 125
    fi
}
