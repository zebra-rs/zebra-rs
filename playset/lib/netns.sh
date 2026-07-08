# Network namespace helpers. Requires common.sh.

netns_exists() {
    local netns=$1
    run ip netns list | awk '{print $1}' | grep -qx "$netns"
}

netns_create() {
    local netns=$1
    if netns_exists "$netns"; then
        netns_delete "$netns"
    fi
    run ip netns add "$netns"
    run_in_netns "$netns" ip link set lo up
}

netns_delete() {
    local netns=$1
    if ! netns_exists "$netns"; then
        return 0
    fi
    run ip netns del "$netns"
}

# Create a veth pair between two existing namespaces and bring both ends up.
# Interface names are chosen by the caller (no address assignment).
netns_connect_pair() {
    local ns_a=$1 iface_a=$2 ns_b=$3 iface_b=$4
    run ip link add "$iface_a" netns "$ns_a" type veth peer name "$iface_b" netns "$ns_b"
    run_in_netns "$ns_a" ip link set "$iface_a" up
    run_in_netns "$ns_b" ip link set "$iface_b" up
}
