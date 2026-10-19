#!/bin/bash
# Bring up the EVPN services over MPLS (eBPF) namespace demo from scratch.

PLAYSET_DEMO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib/playset.sh
source "${PLAYSET_DEMO_DIR}/../lib/playset.sh"
# shellcheck source=topology.sh
source "${PLAYSET_DEMO_DIR}/topology.sh"

# Before any daemon runs, give every CE a readable MAC and turn its IPv6
# off: an idle IPv6 host keeps sending router solicitations and MLD
# reports, broadcast and multicast that would only blur the E-TREE BUM
# counters this lab reads.
playset_after_links() {
    local host ns iface mac
    for host in "${PLAYSET_HOSTS[@]}"; do
        ns=${host%%:*}
        iface=${host#*:}
        mac=${iface#*:}
        iface=${iface%%:*}
        run_in_netns "$ns" sysctl -wq net.ipv6.conf.all.disable_ipv6=1
        run_in_netns "$ns" ip link set dev "$iface" address "$mac"
    done
}

playset_up

# Kernel forwarding OFF on the PEs and the P router: the eBPF engines do
# all the label work, and a successful CE-to-CE ping must prove it (the
# kernel has no action that pops an MPLS label into a bridge or onto a
# port).
for ns in pe1 pe2 pe3 p; do
    run_in_netns "$ns" sysctl -wq net.ipv4.ip_forward=0
done

# The PEs' own iBGP sessions are router-originated TCP entering an
# XDP-forwarded core: they leave the stack with deferred (partial)
# checksums that an XDP redirect never resolves, so the far end would
# drop the segments while ICMP and transit traffic flow fine. Compute
# checksums in software on the core-facing veths instead.
for ns in pe1 pe2 pe3; do
    run_in_netns "$ns" ethtool -K "${ns}-p" tx off
done
