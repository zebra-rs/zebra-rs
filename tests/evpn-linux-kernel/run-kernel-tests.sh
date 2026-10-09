#!/usr/bin/env bash
# Run the root-only kernel exchange tests (`#[ignore]`d in ordinary cargo
# runs), each in its own fresh network namespace so one test's devices and
# routes never reach another's startup dump.
#
# Usage, from the repository root (uses sudo for the namespaces):
#   tests/evpn-linux-kernel/run-kernel-tests.sh [FILTER]
#
# FILTER selects tests by substring (default: all of kernel_exchange_tests).
set -euo pipefail

filter=${1:-}
cd "$(git rev-parse --show-toplevel)"

echo "building zebra-rs tests..." >&2
binary=$(cargo test -p zebra-rs --no-run --message-format=json 2>/dev/null |
    python3 -I -c 'import json, sys
for line in sys.stdin:
    row = json.loads(line)
    if row.get("executable") and row.get("profile", {}).get("test"):
        print(row["executable"])
        break')
if [[ -z "$binary" ]]; then
    echo "could not locate the zebra-rs test binary" >&2
    exit 1
fi

mapfile -t tests < <("$binary" kernel_exchange_tests --list --ignored 2>/dev/null |
    sed -n 's/: test$//p' | grep -F -- "$filter" || true)
if [[ ${#tests[@]} -eq 0 ]]; then
    echo "no kernel exchange tests match '${filter}'" >&2
    exit 1
fi

namespace=""
cleanup() {
    if [[ -n "$namespace" ]]; then
        sudo ip netns delete "$namespace" 2>/dev/null || true
    fi
}
trap cleanup EXIT

failed=()
for test in "${tests[@]}"; do
    namespace="kernel-test-$$-$RANDOM"
    sudo ip netns add "$namespace"
    sudo ip -n "$namespace" link set lo up
    if sudo ip netns exec "$namespace" "$binary" "$test" --exact --include-ignored --nocapture \
        >"/tmp/${namespace}.log" 2>&1; then
        echo "PASS: $test"
        rm -f "/tmp/${namespace}.log"
    else
        echo "FAIL: $test (log: /tmp/${namespace}.log)"
        failed+=("$test")
    fi
    sudo ip netns delete "$namespace"
    namespace=""
done

echo "$(( ${#tests[@]} - ${#failed[@]} ))/${#tests[@]} kernel exchange tests passed"
[[ ${#failed[@]} -eq 0 ]]
