#!/bin/bash
# Bring up the EVPN services over VXLAN (eBPF) namespace demo from scratch.

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
    # A PE's engine sends its encapsulated packets with an XDP redirect,
    # and a veth delivers a redirected frame only when its peer end runs
    # NAPI. P forwards in the kernel (no XDP), so turn GRO on — which
    # gives a veth NAPI — on its PE-facing ends. A physical NIC needs
    # nothing of the kind.
    for iface in p-pe1 p-pe2 p-pe3; do
        run_in_netns p ethtool -K "$iface" gro on
    done
}

playset_up

# Kernel forwarding OFF on the PEs: the eBPF engine switches, encapsulates,
# floods and decapsulates every service, and a successful CE-to-CE ping
# must prove it. The P router is a plain IPv4 router and keeps the kernel.
for ns in pe1 pe2 pe3; do
    run_in_netns "$ns" sysctl -wq net.ipv4.ip_forward=0
done
