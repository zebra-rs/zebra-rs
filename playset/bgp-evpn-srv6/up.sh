#!/bin/bash
# Bring up the EVPN over SRv6 (E-LAN in eBPF) namespace demo from scratch.

PLAYSET_DEMO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib/playset.sh
source "${PLAYSET_DEMO_DIR}/../lib/playset.sh"
# shellcheck source=topology.sh
source "${PLAYSET_DEMO_DIR}/topology.sh"

playset_up

# Kernel forwarding OFF on the PEs: the eBPF data plane bridges and
# encapsulates, and a successful host-to-host ping must prove it (the
# kernel has no End.DT2U/DT2M action anyway).
for ns in pe1 pe2; do
    run_in_netns "$ns" sysctl -wq net.ipv4.ip_forward=0
    run_in_netns "$ns" sysctl -wq net.ipv6.conf.all.forwarding=0
done
