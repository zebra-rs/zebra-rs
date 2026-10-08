# Native OVN EVPN route exchange

OVN 26.09 exchanges EVPN state with a routing speaker through Linux Netlink.
OVN creates the VRF, bridge and fixed-VNI VXLAN devices; zebra-rs adopts them.
The kernel objects are a control-plane mirror. OVN/OVS forwards tenant packets
through `br-int`, including traffic to the external VXLAN fabric.

## Configuration

Enable the OVN adapter before establishing EVPN sessions:

```text
set router bgp global as 65000
set router bgp global router-id 192.0.2.11
set router bgp afi-safi evpn advertise-all-vni true
set router bgp afi-safi evpn ovn-route-exchange true
set router bgp neighbor 172.31.11.1 enabled true
set router bgp neighbor 172.31.11.1 remote-as 65000
set router bgp neighbor 172.31.11.1 afi-safi evpn enabled true

set router bgp vrf ovnvrf100 rd 65000:2000
set vrf ovnvrf100 ipv4 route-target import 65000:2000
set vrf ovnvrf100 ipv4 route-target export 65000:2000
set vrf ovnvrf100 ipv6 route-target import 65000:2000
set vrf ovnvrf100 ipv6 route-target export 65000:2000
set router bgp vrf ovnvrf100 encapsulation vxlan
set router bgp vrf ovnvrf100 evpn l3vni 2000
set router bgp vrf ovnvrf100 evpn router-mac 02:00:00:00:20:01
set router bgp vrf ovnvrf100 evpn advertise-ipv4 true
set router bgp vrf ovnvrf100 evpn advertise-ipv6 true
set router bgp vrf ovnvrf100 afi-safi ipv4 redistribute kernel
set router bgp vrf ovnvrf100 afi-safi ipv6 redistribute kernel
```

Here OVN already owns `ovnvrf100` (table 100), an L3-VNI bridge with VNI
2000, and the L2-VNI bridge(s). Do not configure zebra-rs to recreate their
VXLAN endpoints. Their shadow UDP ports can differ from the real dataplane's
UDP 4789; remote FDB entries carry UDP 4789 without changing those devices.

`redistribute kernel` exports kernel routes from the selected VRF, including
OVN's protocol-84 blackhole routes representing logical connected subnets.
Imported protocol-BGP routes are excluded from kernel ingestion, including
on startup, so they cannot feed back into this redistribution source. The
source is per VRF and exports all eligible kernel prefixes in that VRF;
this configuration does not provide a protocol-84-only policy filter.

## Kernel contract

* Local Type-2 advertisements correlate eligible local FDB rows with ARP/NDP.
  MAC-only, IPv4 and IPv6 bindings have separate NLRI keys and lifetimes.
  `EXT_LEARNED` state is never re-advertised as local state.
* Remote Type-2 bindings install `EXT_LEARNED` / `NOARP` neighbors on the
  owning bridge, plus the remote MAC/VTEP FDB. Withdrawing one binding keeps
  the MAC when another NLRI still references it. Neighbor deletion checks
  ownership before removing an entry replaced by a local neighbor.
* The existing Type-3 path provides remote VTEP flood membership. Locally
  originated routes preserve the selected VTEP independently of the BGP
  session's source interface address.
* Imported Type-5 routes use the remote VTEP as gateway on the L3-VNI bridge,
  with RMAC FDB and neighbor state. IPv6 prefixes use an IPv4-mapped gateway
  and `onlink`; Linux normalizes IPv6 metric zero to 1024. RMAC state remains
  until the last imported prefix using it is withdrawn.
* Kernel-only underlay routes can resolve VTEP reachability. Protocol routes
  take precedence over their kernel shadows to retain transport metadata.
  VRF kernel routes observed before config adoption survive startup replay.

The OVN Type-5 adapter is opt-in and currently targets a unicast VXLAN
nexthop with an IPv4 VTEP. Inner IPv4 and IPv6 are supported. Changing the
mode while routes are active does not replay those routes; configure it at
startup. This change is functional integration, not a 500k-route capacity
qualification or validation of EVPN mobility, multihoming or prefix ECMP.

## Validation

```bash
cargo fmt --all -- --check
cargo test --workspace --exclude bdd
cargo clippy --workspace --all-targets -- -D warnings
```

The external OVN comparison lab uses two Kind hosts, two Arista cEOS leaves,
L2 VNI 1000 and L3 VNI 2000. Its acceptance checks cover Type-2/3/5 exchange,
IPv4/IPv6 kernel and OVN Southbound state, bidirectional switching/routing,
VXLAN packet captures, access-link withdrawal/restore, routed-subnet
withdrawal/restore, and routing-speaker restart. Functional results and their
scope are recorded in `docs/validation/ovn-ceos-kind.md`.
