# Shared helpers for Linux namespace demo kits under playset/.
# Source from a demo script after setting PLAYSET_DEMO_DIR.

: "${PLAYSET_DEMO_DIR:?PLAYSET_DEMO_DIR must be set before sourcing common.sh}"

set -euo pipefail

PLAYSET_ROOT="$(cd "${PLAYSET_DEMO_DIR}/.." && pwd)"

run() {
    sudo "$@"
}

run_in_netns() {
    local netns=$1
    shift
    run ip netns exec "$netns" "$@"
}

playset_cleanup_logs() {
    rm -f "${PLAYSET_DEMO_DIR}"/*.log "${PLAYSET_DEMO_DIR}"/*.pid "${PLAYSET_DEMO_DIR}"/nohup.out
}
