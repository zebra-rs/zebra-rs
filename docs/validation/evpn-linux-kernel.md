# EVPN Linux kernel forwarding validation

The [standalone namespace test](../../tests/evpn-linux-kernel/README.md)
passed **38/38 checks** on 2026-10-08. Two zebra-rs speakers exchanged
EVPN Type-2/3/5 state and forwarded tenant traffic through Linux bridge,
VXLAN and VRF devices. No OVN, OVS, FRR, cEOS or containers participated.

Coverage includes IPv4/IPv6 switching and routing in both directions,
VTEPs distinct from BGP transport addresses, kernel-only underlay routes,
Type-2 IPv4 withdrawal with MAC/IPv6 survival, static-blackhole Type-5
redistribution from startup VRF state, prefix withdrawal and final cleanup
of both IPv4 and mapped-IPv6 RMAC neighbors. The
[JSON report](evpn-linux-kernel.json) records each check and the tested
binary's SHA-256. The binary was built from the generic implementation
before its documentation and test results were committed.

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
