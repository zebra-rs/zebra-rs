#!/bin/bash
# Single-box free5GC + free-ran-ue + zebra-rs/cradle UPF lab topology.
#
#  host (root ns): free5GC CP on 127.0.0.x, mongodb, webconsole
#   |- mrHost 10.0.1.1/24  <-veth->  mupran:mrVeth 10.0.1.2/24   (N2 + N3 transit)
#   |- muHost 10.0.12.1/24 <-veth->  mupupf:mun3  10.0.12.2/24   (N4 + N3)
#  mupran: free-ran-ue gNB (N2/N3 on 10.0.1.2, UE link on 127.0.0.1) + UE (TUN)
#  mupupf: zebra-rs + cradle; ONE VRF mobile (table 1) binds both st1+st2:
#          mun6 10.0.60.1/24 — the single N6 leg (issue #1947)
#  mupdn:  mdn6 10.0.60.2/24 (DL ingress AND UL egress / ping target)
#          route 10.60.0.0/16 via 10.0.60.1
set -ex

ip netns add mupran
ip netns add mupupf
ip netns add mupdn

ip link add mrHost type veth peer name mrVeth netns mupran
ip link add muHost type veth peer name mun3 netns mupupf
ip link add mun6 netns mupupf type veth peer name mdn6 netns mupdn

# host side
ip addr add 10.0.1.1/24 dev mrHost
ip addr add 10.0.12.1/24 dev muHost
ip link set mrHost up
ip link set muHost up
sysctl -wq net.ipv4.ip_forward=1

# ran ns: gNB N2/N3 address; loopback for the gNB<->UE link
ip netns exec mupran ip link set lo up
ip netns exec mupran ip addr add 10.0.1.2/24 dev mrVeth
ip netns exec mupran ip link set mrVeth up
ip netns exec mupran ip route add default via 10.0.1.1

# upf ns: only mun3 gets a kernel address here; mun6 is addressed and
# VRF-enslaved by zebra-rs from upf.yaml. Kernel forwarding OFF: eBPF forwards.
ip netns exec mupupf ip link set lo up
ip netns exec mupupf ip addr add 10.0.12.2/24 dev mun3
ip netns exec mupupf ip link set mun3 up
ip netns exec mupupf ip link set mun6 up
ip netns exec mupupf ip route add default via 10.0.12.1
ip netns exec mupupf sysctl -wq net.ipv4.ip_forward=0

# dn ns. TX checksum offload OFF: a veth leaves TCP checksums uncomputed
# (CHECKSUM_PARTIAL), cradle's GTP encap forwards those raw bytes, and the
# free-ran-ue UE injects them into ueTun0 where the kernel validates — and
# drops — the bad inner checksum. ICMP is unaffected (ping checksums in
# software), so a ping-clean lab still fails TCP without this. Hardware
# NICs compute the checksum at egress, so this is a veth-lab artifact.
ip netns exec mupdn ip link set lo up
ip netns exec mupdn ip addr add 10.0.60.2/24 dev mdn6
ip netns exec mupdn ip link set mdn6 up
ip netns exec mupdn ethtool -K mdn6 tx off
ip netns exec mupdn ip route add 10.60.0.0/16 via 10.0.60.1

echo "topology up"
