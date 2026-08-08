#!/usr/bin/env bash
#
# Baseline FPM scenario: the route shapes the zebra-rs encoder has to get
# right before anything else matters. Deliberately protocol-free — no BGP
# peer, no convergence — so the capture is small, deterministic and easy
# to diff by eye.
#
# Run inside the rig container by capture.sh.

set -uo pipefail

v() { vtysh -c "configure terminal" -c "$1" >/dev/null; }

echo "  connected routes are already in flight from interface setup"

echo "  single-nexthop IPv4"
v "ip route 10.100.0.0/24 10.0.0.2"

echo "  single-nexthop IPv4, interface nexthop (onlink)"
v "ip route 10.100.1.0/24 dum1"

echo "  ECMP IPv4 — three legs, the RTA_MULTIPATH case"
v "ip route 10.100.2.0/24 10.0.0.2"
v "ip route 10.100.2.0/24 10.0.1.2"
v "ip route 10.100.2.0/24 10.0.2.2"

echo "  route replace — same prefix, nexthop set shrinks to two"
v "no ip route 10.100.2.0/24 10.0.2.2"

# Note: the trailing number is FRR's administrative *distance*, which is
# a RIB-selection input and never reaches the wire. Kept because it
# exercises a distinct staticd path, but do not expect RTA_PRIORITY here.
echo "  non-default administrative distance"
v "ip route 10.100.3.0/24 10.0.0.2 200"

echo "  blackhole and unreachable"
v "ip route 10.100.4.0/24 blackhole"
v "ip route 10.100.5.0/24 reject"

echo "  default route"
v "ip route 0.0.0.0/0 10.0.0.254"

echo "  host route (/32)"
v "ip route 10.100.6.7/32 10.0.0.2"

echo "  single-nexthop IPv6"
v "ipv6 route 2001:db8:100::/64 2001:db8::2"

echo "  ECMP IPv6"
v "ipv6 route 2001:db8:101::/64 2001:db8::2"
v "ipv6 route 2001:db8:101::/64 2001:db8:1::2"

echo "  IPv6 host route (/128) and default"
v "ipv6 route 2001:db8:102::7/128 2001:db8::2"
v "ipv6 route ::/0 2001:db8::fe"

sleep 2

echo "  deletes — the RTM_DELROUTE side"
v "no ip route 10.100.0.0/24 10.0.0.2"
v "no ip route 10.100.4.0/24 blackhole"
v "no ipv6 route 2001:db8:100::/64 2001:db8::2"

echo "  withdrawing a connected route by downing its link"
ip link set dum2 down

sleep 2
echo "  scenario complete"
