#!/usr/bin/env bash
#
# VRF routes over FPM.
#
# The one encoding the plain-unicast capture cannot show. FPM's table
# field is not a kernel routing-table id: the SONiC dplane plugin
# substitutes the VRF *device ifindex* for it ("Put vrf if_index instead
# of table id", dplane_fpm_sonic.c:1232-1242), and `fpmsyncd` resolves
# that value with getIfName() and insists the result starts with `Vrf`
# (routesync.cpp:920-942).
#
# So this scenario deliberately produces a case where the table id and
# the ifindex are different numbers — table 100, whatever ifindex the
# device lands on — because an encoder that confuses them would still
# look correct if they happened to match.
#
# Run inside the rig container by capture.sh.

set -uo pipefail

v() { vtysh -c "configure terminal" -c "$1" >/dev/null; }

echo "  creating VRF Vrf1 (kernel table 100)"
# The name matters: fpmsyncd rejects a VRF whose interface name does not
# start with VRF_PREFIX ("Vrf"), which is SONiC's convention.
ip link add Vrf1 type vrf table 100
ip link set Vrf1 up

echo "  enslaving dum1 to Vrf1"
ip link set dum1 master Vrf1
# Enslaving moves the connected routes into the VRF's table; re-add the
# addresses so the nexthops below resolve.
ip addr add 10.0.1.1/24 dev dum1 2>/dev/null || true
ip -6 addr add 2001:db8:1::1/64 dev dum1 2>/dev/null || true
ip link set dum1 up

echo "  table id vs ifindex (these must differ for the capture to be useful)"
echo "    table=100 ifindex=$(cat /sys/class/net/Vrf1/ifindex)"

sleep 2

echo "  static routes in the VRF"
v "ip route 10.200.0.0/24 10.0.1.2 vrf Vrf1"
v "ip route 10.200.1.0/24 10.0.1.2 vrf Vrf1"
v "ipv6 route 2001:db8:200::/64 2001:db8:1::2 vrf Vrf1"

echo "  a default-VRF route alongside, so both encodings are in one trace"
v "ip route 10.100.0.0/24 10.0.0.2"

sleep 2

echo "  deleting one VRF route"
v "no ip route 10.200.1.0/24 10.0.1.2 vrf Vrf1"

sleep 2
echo "  scenario complete"
