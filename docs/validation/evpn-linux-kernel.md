# EVPN Linux kernel forwarding validation

The [standalone namespace test](../../tests/evpn-linux-kernel/README.md)
passed **125/125 checks** on 2026-10-09. Two zebra-rs speakers exchanged
EVPN Type-2/3/5 state and forwarded tenant traffic through Linux bridge,
VXLAN and VRF devices. No OVN, OVS, FRR, cEOS or containers participated.

Coverage includes IPv4/IPv6 switching and routing in both directions,
VTEPs distinct from BGP transport addresses, kernel-only underlay routes,
Type-2 IPv4 withdrawal with MAC/IPv6 survival, static-blackhole Type-5
redistribution from startup VRF state, prefix withdrawal and final cleanup
of both IPv4 and mapped-IPv6 RMAC neighbors. Recovery checks remove
bridge Type-5 state in the kernel five ways (L3-VNI bridge admin flap,
VXLAN carrier flap, neighbor/FDB flush, VXLAN detach and re-attach,
external route deletion) and require routes, RMAC neighbors and FDB, and
routed pings to return. A bridge-move check moves the L3-VNI VXLAN to a
second bridge and back; both bridges keep carrier through a dummy port,
so only zebra-rs can remove the RMAC neighbors left on the old one. With
the link and neighbor recovery hooks disabled, nothing recovers after the
first (admin flap) scenario; with only route-deletion recovery and
bridge-move cleanup disabled, exactly those eight checks fail. A
crash-and-restart scenario kills one speaker with SIGKILL, changes its
configuration and the peer's advertisements while it is down, and
restarts it: leftovers its fresh routes replace are kept, a removed
static and a withdrawn Type-5 are swept, an operator `proto static`
route survives, and a pre-`RTPROT_ZEBRA` copy of a configured static is
adopted. Floating statics (two priorities each) check that a removed
one leaves no priority behind and a changed backup priority replaces the
old one. A binary built without leftover handling fails exactly the
eight leftover checks; one handling only a single priority per leftover
fails the four floating-static checks. A MAC mobility scenario moves a station
behind the other speaker and back and checks both sides settle and stay
settled; a build that installs a remote route over a local MAC regardless
of sequence number fails to keep the returned station local. The
[JSON report](evpn-linux-kernel.json) records each check and the tested
binary's SHA-256.

The existing `playset/bgp-evpn-vxlan4` topology also established EVPN and
passed two pings in each direction between `h1` and `h2`. That topology
uses zebra-created metadata-mode VXLAN with the new Type-5 option disabled.
It provides compatibility coverage for that existing Linux L2 dataplane.

Run the standalone test from the repository root:

```bash
cargo build -p zebra-rs -p vtyctl
sudo python3 tests/evpn-linux-kernel/test.py --output /tmp/evpn-kernel-results.json
```

The test uses flat fixed-VNI bridges and IPv4 VTEPs. It does not qualify
VLAN-aware fixed-VNI bridges, IPv6 VTEPs, mobility, multihoming,
prefix ECMP or 500k-route capacity. The
[OVN/cEOS report](ovn-ceos-kind.md) describes earlier prototype validation,
with its own hashes and configuration; it is separate evidence.
