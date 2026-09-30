#!/bin/bash
# Bring up the IS-IS TE metric / STAMP namespace demo from scratch.

PLAYSET_DEMO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib/playset.sh
source "${PLAYSET_DEMO_DIR}/../lib/playset.sh"
# shellcheck source=topology.sh
source "${PLAYSET_DEMO_DIR}/topology.sh"

# Give every link its propagation delay as a netem qdisc on both veth
# ends. It runs between link creation and daemon start (the
# playset_after_links hook), so STAMP's first damped export already
# measures the delayed link rather than a bare veth.
playset_after_links() {
    local link ns_a iface_a ns_b iface_b entry delay
    for link in "${PLAYSET_LINKS[@]}"; do
        IFS=: read -r ns_a iface_a ns_b iface_b <<< "$link"
        delay=""
        for entry in "${PLAYSET_LINK_DELAYS[@]}"; do
            if [[ "${entry%%:*}" == "$iface_a" ]]; then
                delay="${entry#*:}"
            fi
        done
        : "${delay:?no delay in PLAYSET_LINK_DELAYS for ${iface_a}}"
        echo "link delay: ${iface_a} <-> ${iface_b} ${delay}ms each way"
        run_in_netns "$ns_a" tc qdisc replace dev "$iface_a" root netem delay "${delay}ms"
        run_in_netns "$ns_b" tc qdisc replace dev "$iface_b" root netem delay "${delay}ms"
    done
}

playset_up
