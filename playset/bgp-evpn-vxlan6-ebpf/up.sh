#!/bin/bash
# Bring up the BGP EVPN VXLAN over IPv6 underlay (eBPF data plane) demo
# from scratch.

PLAYSET_DEMO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib/playset.sh
source "${PLAYSET_DEMO_DIR}/../lib/playset.sh"
# shellcheck source=topology.sh
source "${PLAYSET_DEMO_DIR}/topology.sh"

playset_up

# Kernel forwarding OFF (both families — the underlay is IPv6) on the
# VTEPs: the eBPF engine encapsulates, floods and decapsulates, and a
# successful host-to-host ping must prove it — the kernel VXLAN path
# stays configured but never sees a frame.
for ns in vtep1 vtep2; do
    run_in_netns "$ns" sysctl -wq net.ipv4.ip_forward=0
    run_in_netns "$ns" sysctl -wq net.ipv6.conf.all.forwarding=0
done
