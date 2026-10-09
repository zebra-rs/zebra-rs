# EVPN with adopted Linux bridge, VXLAN and VRF devices

This automated test runs two zebra-rs speakers and four tenant hosts in
six isolated Linux network namespaces. It requires no OVN, OVS, FRR, cEOS,
container runtime, or Python packages beyond the standard library.

Each speaker adopts two operator-created fixed-VNI VXLAN devices: VNI 1000
for switching and VNI 2000 for routing in `tenant100` (table 100). The
IPv4 VTEPs (`198.51.100.1/2`) differ from BGP transport addresses
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
It also removes bridge Type-5 state behind the daemon (L3-VNI bridge
admin flap, VXLAN carrier flap, neighbor/FDB flush, VXLAN detach and
re-attach, external route deletion) and checks that routes, RMAC adjacency
and routing recover. It moves the L3-VNI VXLAN to a second bridge and
back, checking that no RMAC neighbors remain on the bridge it left.
Real pings traverse the Linux VXLAN dataplane.

Build the binaries and run from the repository root on Linux with
iproute2, ping, and network namespace privileges:

```bash
cargo build -p zebra-rs -p vtyctl
sudo python3 tests/evpn-linux-kernel/test.py --output /tmp/evpn-kernel-results.json
```

The script generates unique namespace names and cleans them up, including
its routing processes, after success or failure. Failures produce route,
neighbor, FDB, EVPN RIB and daemon log diagnostics in the JSON report.

This covers flat bridges with fixed-VNI VXLAN and IPv4 VTEPs. Existing
zebra-created metadata-mode VXLAN playsets remain separate compatibility
coverage. This test does not qualify VLAN-aware fixed-VNI bridges,
IPv6 VTEPs, multihoming, mobility, prefix ECMP, or route capacity.
