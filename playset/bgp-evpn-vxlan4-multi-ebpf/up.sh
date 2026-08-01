#!/bin/bash
# Bring up the BGP EVPN VXLAN multi-tenant (eBPF data plane) demo from
# scratch.

PLAYSET_DEMO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib/playset.sh
source "${PLAYSET_DEMO_DIR}/../lib/playset.sh"
# shellcheck source=topology.sh
source "${PLAYSET_DEMO_DIR}/topology.sh"

playset_up

# Kernel forwarding OFF on the VTEPs: the eBPF engine encapsulates,
# floods and decapsulates, and a successful host-to-host ping must prove
# it — the kernel VXLAN path stays configured but never sees a frame.
for ns in vtep1 vtep2 vtep3; do
    run_in_netns "$ns" sysctl -wq net.ipv4.ip_forward=0
done
