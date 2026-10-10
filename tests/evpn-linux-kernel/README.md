# EVPN with adopted Linux bridge, VXLAN and VRF devices

This automated test runs two zebra-rs speakers and four tenant hosts in
six isolated Linux network namespaces. It requires no OVN, OVS, FRR, cEOS,
container runtime, or Python packages beyond the standard library.

Each speaker adopts two operator-created fixed-VNI VXLAN devices: VNI 1000
for switching and VNI 2000 for routing in `tenant100` (table 100). The
IPv4 VTEPs (`198.51.100.1/2`), or IPv6 VTEPs (`2001:db8:100::1/2`) over an
IPv6 underlay with `--ipv6-vtep`, differ from BGP transport addresses
(`192.0.2.1/2`). Static underlay routes provide VTEP reachability.
The feature is enabled with:

```text
set router bgp afi-safi evpn advertise-all-vni true
set router bgp afi-safi evpn kernel-route-exchange true
set router bgp vrf tenant100 afi-safi ipv4 redistribute kernel
set router bgp vrf tenant100 afi-safi ipv6 redistribute kernel
```

The script checks dual-stack Type-2 neighbor installation and switching,
Type-5 VRF route installation and routing, redistribution of ordinary
static blackholes present before startup, IPv4 binding withdrawal with
IPv6/MAC survival, and prefix withdrawal with shared RMAC survival.
It checks ARP/ND suppression: a host resolving a remote host's address is
answered by its own speaker, and no ARP request or neighbor solicitation
enters the VXLAN overlay (needs `tcpdump`; skipped and recorded without
it). It also removes bridge Type-5 state behind the daemon (L3-VNI bridge
admin flap, VXLAN carrier flap, neighbor/FDB flush, VXLAN detach and
re-attach, external route deletion) and checks that routes, RMAC adjacency
and routing recover. It moves the L3-VNI VXLAN to a second bridge and
back, checking that no RMAC neighbors remain on the bridge it left.
It moves a station's MAC and IP from one speaker to the other and back,
checking that each side ends with the station local where it is and
remote toward the other VTEP where it is not, and that this holds.
It puts one MAC/IP behind both speakers, talking alternately, with
`dup-addr-detection max-moves 3 freeze permanent`: the speaker that sees
the third move detects the duplicate and freezes it, the station stays
local on both sides, and `clear bgp evpn dup-addr` releases it.
Finally it kills one speaker, changes its configuration and the peer's
advertisements while it is down, and restarts it with a short
`--leftover-sweep-time`. Leftovers its fresh routes replace are kept,
the rest (a removed static, a withdrawn Type-5) are swept, an operator
`proto static` route survives, and a pre-`RTPROT_ZEBRA` copy of a
configured static is adopted.
Floating static routes exercise removal of both priorities and replacement
of the old backup priority in IPv4 and IPv6.
Real pings traverse the Linux VXLAN dataplane.

Build the binaries and run from the repository root on Linux with
iproute2, ping, and network namespace privileges:

```bash
cargo build -p zebra-rs -p vtyctl
sudo python3 tests/evpn-linux-kernel/test.py --output /tmp/evpn-kernel-results.json
sudo python3 tests/evpn-linux-kernel/test.py --ipv6-vtep --output /tmp/evpn-kernel-ipv6-results.json
```

The script generates unique namespace names and cleans them up, including
its routing processes, after success or failure. Failures produce route,
neighbor, FDB, EVPN RIB and daemon log diagnostics in the JSON report.

This covers flat bridges with fixed-VNI VXLAN and IPv4 or IPv6 VTEPs.
Existing zebra-created metadata-mode VXLAN playsets remain separate
compatibility coverage. This test does not qualify VLAN-aware fixed-VNI
bridges, multihoming, prefix ECMP, or route capacity.

Kernel exchange regression tests cover self-generated route notifications,
external route eligibility, and blackhole/unicast replacement at multiple
priorities in IPv4, IPv6 and VRF tables:

```bash
cargo test -p zebra-rs kernel_exchange_tests
```

Additional tests check actual static-route retention, shared-IP neighbor
ownership during unrelated MAC/IP updates and withdrawals, and cleanup of
every leftover priority during sweeps and floating-static replacement,
removal of SRv6 leftovers nothing reinstalled (keeping reinstalled and
operator SIDs), and multipath kernel routes changing one next hop at a time (IPv6
next-hop deletion, IPv4 append, replace and delete) through the real
Netlink notifications.
The leftover tests cover unicast, ECMP, blackhole and mixed paths in
IPv4, IPv6, main and VRF tables. They
are ignored by ordinary cargo runs because they need root in an isolated
network namespace. Run them from the repository root; each runs in its own
fresh namespace (sudo creates and removes it):

```bash
tests/evpn-linux-kernel/run-kernel-tests.sh            # all of them
tests/evpn-linux-kernel/run-kernel-tests.sh multipath  # those matching a substring
```
