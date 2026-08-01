#!/bin/bash
# The N4-separated FAITHFUL variant of setup-topo.sh (the interwork/direct
# split with the N3 port inside kernel VRF N3 — see the README's variant
# section and book ch-02-35):
#
#  host (root ns): free5GC CP on 127.0.0.x, mongodb, webconsole
#   |- mrHost  10.0.1.1/24  <-veth->  mupran:mrVeth 10.0.1.2/24  (N2 + N3 transit)
#   |- muHost  10.0.12.1/24 <-veth->  mupupf:mun3  10.0.12.2/24  (N3 ONLY — VRF N3)
#   |- mu4Host 10.0.11.1/24 <-veth->  mupupf:mun4  10.0.11.2/24  (N4 ONLY — global)
#  mupran: free-ran-ue gNB (N2/N3 on 10.0.1.2) + UE (TUN)
#  mupupf: zebra-rs + cradle; VRF N3 (table 1, interwork segment: mun3, the
#          gNB static route, the decap PDR match context) + VRF N6 (table 2,
#          direct segment: mun6, the UE routes). The PFCP socket is NOT
#          VRF-aware, so N4 rides its own global-table link (mun4).
#  mupdn:  mdn6 10.0.60.2/24; route 10.60.0.0/16 via 10.0.60.1
set -ex

ip netns add mupran
ip netns add mupupf
ip netns add mupdn

ip link add mrHost type veth peer name mrVeth netns mupran
ip link add muHost type veth peer name mun3 netns mupupf
ip link add mu4Host type veth peer name mun4 netns mupupf
ip link add mun6 netns mupupf type veth peer name mdn6 netns mupdn

# host side
ip addr add 10.0.1.1/24 dev mrHost
ip addr add 10.0.12.1/24 dev muHost
ip addr add 10.0.11.1/24 dev mu4Host
ip link set mrHost up
ip link set muHost up
ip link set mu4Host up
sysctl -wq net.ipv4.ip_forward=1

# ran ns: gNB N2/N3 address; loopback for the gNB<->UE link
ip netns exec mupran ip link set lo up
ip netns exec mupran ip addr add 10.0.1.2/24 dev mrVeth
ip netns exec mupran ip link set mrVeth up
ip netns exec mupran ip route add default via 10.0.1.1

# upf ns: mun3 (N3) and mun4 (N4) get their kernel addresses here; zebra-rs
# enslaves mun3 into VRF N3 and mun6 into VRF N6 from upf-n3vrf.yaml (the
# connected routes then live in tables 1 / 2). NO global default: the only
# global-table traffic is PFCP, whose SMF peer (10.0.11.1) is on-link on
# mun4. The gNB static route (10.0.1.0/24 via 10.0.12.1) is installed by
# zebra-rs into VRF N3 (`router static vrf N3`). Kernel forwarding OFF:
# eBPF forwards.
ip netns exec mupupf ip link set lo up
ip netns exec mupupf ip addr add 10.0.12.2/24 dev mun3
ip netns exec mupupf ip addr add 10.0.11.2/24 dev mun4
ip netns exec mupupf ip link set mun3 up
ip netns exec mupupf ip link set mun4 up
ip netns exec mupupf ip link set mun6 up
ip netns exec mupupf sysctl -wq net.ipv4.ip_forward=0

# dn ns (see setup-topo.sh for the TX-checksum-offload note)
ip netns exec mupdn ip link set lo up
ip netns exec mupdn ip addr add 10.0.60.2/24 dev mdn6
ip netns exec mupdn ip link set mdn6 up
ip netns exec mupdn ethtool -K mdn6 tx off
ip netns exec mupdn ip route add 10.60.0.0/16 via 10.0.60.1

echo "topology up (N4-separated faithful variant)"
