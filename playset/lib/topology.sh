# Topology orchestration. Requires common.sh, netns.sh, and zebra-rs.sh.
# Each demo defines PLAYSET_NAMESPACES, PLAYSET_LINKS, PLAYSET_DAEMONS,
# and PLAYSET_ROUTERS before calling these functions.

playset_teardown() {
    echo "teardown: stop zebra-rs"
    playset_stop_zebra
    local netns
    for netns in "${PLAYSET_NAMESPACES[@]}"; do
        echo "teardown: delete namespace ${netns}"
        netns_delete "$netns"
    done
}

playset_create_namespaces() {
    local netns
    for netns in "${PLAYSET_NAMESPACES[@]}"; do
        echo "create namespace: ${netns}"
        netns_create "$netns"
    done
}

playset_create_links() {
    local link ns_a iface_a ns_b iface_b
    for link in "${PLAYSET_LINKS[@]}"; do
        IFS=: read -r ns_a iface_a ns_b iface_b <<< "$link"
        echo "create link: ${iface_a} (${ns_a}) <-> ${iface_b} (${ns_b})"
        netns_connect_pair "$ns_a" "$iface_a" "$ns_b" "$iface_b"
    done
}

playset_start_daemons() {
    local netns
    for netns in "${PLAYSET_DAEMONS[@]}"; do
        echo "start zebra-rs: ${netns}"
        playset_start_zebra "$netns"
    done
}

playset_up() {
    echo "bring up"
    echo "runtime dir: ${PLAYSET_RUN_DIR}"
    playset_teardown
    echo "cleanup logs"
    playset_cleanup_logs
    playset_create_namespaces
    playset_create_links
    playset_start_daemons
    # Nothing left in the bring-up waits on this, but the labs that add
    # steps after `playset_up` (kernel forwarding off, ethtool, ND warm-up
    # pings) used to run a full config-apply cycle after the daemons came
    # up. Keep the settle so their timing is unchanged.
    echo "sleep 3sec"
    sleep 3
}
