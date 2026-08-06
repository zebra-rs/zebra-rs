# Shared helpers for Linux namespace demo kits under playset/.
# Source from a demo script after setting PLAYSET_DEMO_DIR.

: "${PLAYSET_DEMO_DIR:?PLAYSET_DEMO_DIR must be set before sourcing common.sh}"

set -euo pipefail

PLAYSET_ROOT="$(cd "${PLAYSET_DEMO_DIR}/.." && pwd)"

# Runtime state (*.pid, *.log, and each router's startup config) lives
# outside the demo directory so the labs also run from a read-only install
# location such as /usr/share/zebra-rs/playset. Override with
# PLAYSET_RUN_DIR.
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

# Wipe the previous run's state. The seeded startup configs go with it:
# `up.sh` re-seeds them from the demo directory, so the lab always comes up
# as its README documents it and a `save` made during the last run is
# deliberately not carried over. Set PLAYSET_KEEP_CONFIG=1 to keep the
# copies (and the edits saved into them) across a bring-up.
playset_cleanup_run_dir() {
    rm -f "${PLAYSET_RUN_DIR}"/*.log "${PLAYSET_RUN_DIR}"/*.pid "${PLAYSET_RUN_DIR}"/nohup.out
    if [[ "${PLAYSET_KEEP_CONFIG:-0}" != 1 ]]; then
        rm -f "${PLAYSET_RUN_DIR}"/*.yaml
    fi
}
