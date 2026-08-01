#!/bin/bash
# Bring up the EVPN VPWS (E-Line over SRv6) namespace demo from scratch.

PLAYSET_DEMO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib/playset.sh
source "${PLAYSET_DEMO_DIR}/../lib/playset.sh"
# shellcheck source=topology.sh
source "${PLAYSET_DEMO_DIR}/topology.sh"

playset_up

# Kernel forwarding OFF on the PEs: the eBPF data plane does the label
# work, and a successful CE-to-CE ping must prove it (the kernel has no
# End.DX2 action anyway).
for ns in pe1 pe2; do
    run_in_netns "$ns" sysctl -wq net.ipv4.ip_forward=0
    run_in_netns "$ns" sysctl -wq net.ipv6.conf.all.forwarding=0
done
