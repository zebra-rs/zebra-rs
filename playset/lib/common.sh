# Shared helpers for Linux namespace demo kits under playset/.
# Source from a demo script after setting PLAYSET_DEMO_DIR.

: "${PLAYSET_DEMO_DIR:?PLAYSET_DEMO_DIR must be set before sourcing common.sh}"

set -euo pipefail

PLAYSET_ROOT="$(cd "${PLAYSET_DEMO_DIR}/.." && pwd)"

# Runtime state (*.pid, *.log) lives outside the demo directory so a lab
# run leaves nothing behind but the config each node was given. Override
# with PLAYSET_RUN_DIR.
: "${PLAYSET_RUN_DIR:=/tmp/zebra-rs-playset/$(basename "${PLAYSET_DEMO_DIR}")}"
mkdir -p "${PLAYSET_RUN_DIR}"

run() {
    sudo "$@"
}

run_in_netns() {
    local netns=$1
    shift
    run ip netns exec "$netns" "$@"
}

# Wipe the previous run's logs and pid files. The node configs are not in
# here — they are the lab's own <node>.yaml, edited in place — so a config
# saved from the vty survives every bring-up.
playset_cleanup_logs() {
    rm -f "${PLAYSET_RUN_DIR}"/*.log "${PLAYSET_RUN_DIR}"/*.pid "${PLAYSET_RUN_DIR}"/nohup.out
}
