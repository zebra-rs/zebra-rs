#!/bin/bash
# Bring up the EVPN over MPLS (E-LAN in eBPF) namespace demo from scratch.

PLAYSET_DEMO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib/playset.sh
source "${PLAYSET_DEMO_DIR}/../lib/playset.sh"
# shellcheck source=topology.sh
source "${PLAYSET_DEMO_DIR}/topology.sh"

playset_up

# Kernel forwarding OFF on the PEs and the P router: the eBPF data plane
# does the label work, and a successful host-to-host ping must prove it
# (the kernel has no action that pops an MPLS label into a bridge).
for ns in pe1 p pe2; do
    run_in_netns "$ns" sysctl -wq net.ipv4.ip_forward=0
done

# The PEs' own iBGP session is router-originated TCP entering an
# XDP-forwarded core: it leaves the stack with deferred (partial)
# checksums that an XDP redirect never resolves, so the far end would
# drop the segments while ICMP and transit traffic flow fine. Compute
# checksums in software on the core-facing veths instead.
run_in_netns pe1 ethtool -K pe1-p tx off
run_in_netns pe2 ethtool -K pe2-p tx off
