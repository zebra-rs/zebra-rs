#!/bin/bash
# Bring up the EVPN over MPLS between IPv6 PEs (E-LAN in eBPF) namespace
# demo from scratch.

PLAYSET_DEMO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib/playset.sh
source "${PLAYSET_DEMO_DIR}/../lib/playset.sh"
# shellcheck source=topology.sh
source "${PLAYSET_DEMO_DIR}/topology.sh"

playset_up

# Kernel forwarding OFF (both families — the core is IPv6) on the PEs
# and the P router: the eBPF data plane does the label work, and a
# successful host-to-host ping must prove it (the kernel has no action
# that pops an MPLS label into a bridge).
for ns in pe1 p pe2; do
    run_in_netns "$ns" sysctl -wq net.ipv4.ip_forward=0
    run_in_netns "$ns" sysctl -wq net.ipv6.conf.all.forwarding=0
done

# The PEs' own iBGP session is router-originated TCP entering an
# XDP-forwarded core: it leaves the stack with deferred (partial)
# checksums that an XDP redirect never resolves, so the far end would
# drop the segments while ICMP and transit traffic flow fine. Compute
# checksums in software on the core-facing veths instead.
run_in_netns pe1 ethtool -K pe1-p tx off
run_in_netns pe2 ethtool -K pe2-p tx off

# The P's eBPF egress rewrite needs its neighbors' MACs: its own kernel
# never originates toward the PEs, so one warm-up ping each resolves ND
# and the netlink monitor tees the entries to the engine.
run_in_netns p ping -c 1 -W 2 2001:db8:12::1 > /dev/null 2>&1 || true
run_in_netns p ping -c 1 -W 2 2001:db8:23::2 > /dev/null 2>&1 || true
