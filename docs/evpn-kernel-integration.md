# EVPN integration with Linux bridge, VXLAN and VRF

zebra-rs exchanges EVPN state through the standard Linux Netlink interface.
It can adopt existing VRF, bridge and fixed-VNI VXLAN devices, regardless of
which tool created them. Remote Type-2 MAC/IP bindings populate bridge FDB
and neighbor tables. Type-5 prefixes populate tenant VRF routes and the
L3-VNI bridge adjacency. Device discovery uses kernel attributes rather
than device names, and route ingestion has no application-specific
protocol-number requirement.

This interface is intended for Linux EVPN forwarding and applications that
consume kernel state. OVN is one such consumer; its integration lab is
additional evidence, not a prerequisite for using the feature.

## Configuration

Enable bridge-based kernel route installation before establishing EVPN sessions:

```text
set router bgp global as 65000
set router bgp global router-id 192.0.2.11
set router bgp afi-safi evpn advertise-all-vni true
set router bgp afi-safi evpn kernel-route-exchange true
set router bgp neighbor 172.31.11.1 enabled true
set router bgp neighbor 172.31.11.1 remote-as 65000
set router bgp neighbor 172.31.11.1 afi-safi evpn enabled true

set router bgp vrf tenant100 rd 65000:2000
set vrf tenant100 ipv4 route-target import 65000:2000
set vrf tenant100 ipv4 route-target export 65000:2000
set vrf tenant100 ipv6 route-target import 65000:2000
set vrf tenant100 ipv6 route-target export 65000:2000
set router bgp vrf tenant100 encapsulation vxlan
set router bgp vrf tenant100 evpn l3vni 2000
set router bgp vrf tenant100 evpn router-mac 02:00:00:00:20:01
set router bgp vrf tenant100 evpn advertise-ipv4 true
set router bgp vrf tenant100 evpn advertise-ipv6 true
set router bgp vrf tenant100 afi-safi ipv4 redistribute kernel
set router bgp vrf tenant100 afi-safi ipv6 redistribute kernel
```

Here the operator has already created `tenant100` (table 100), an L3-VNI bridge with VNI
2000, and the L2-VNI bridge(s). Do not configure zebra-rs to recreate their
VXLAN endpoints. For Linux forwarding, the devices must use UDP 4789.
Applications consuming kernel state may instead use devices as mirrors
of a separate dataplane; remote FDB entries still carry UDP 4789.

`redistribute kernel` exports kernel routes from the selected VRF, including
static or externally installed blackhole prefixes, independent of their
originating protocol number. Protocol-BGP routes in VRF tables (imported
routes) are excluded from kernel ingestion, so they cannot feed back into
this redistribution source. Main-table protocol-BGP routes stay visible,
because another daemon may own the underlay. IPv6
interface prefix routes (`proto kernel`) and link-local prefixes are not
ingested; connected routes come from the interface addresses. The
source is per VRF and exports all eligible kernel prefixes in that VRF;
this configuration does not provide a route-protocol policy filter.
Kernel events matching a route zebra-rs already installed (prefix, table,
protocol and priority) are excluded from kernel ingestion, so static and
IGP output cannot displace its owning route as a distance-0 kernel entry.
External static routes remain eligible. Kernel routes at different
priorities are retained independently; replacing a blackhole with a
unicast route, or the reverse, updates the selected route and redistribution. At
one priority the RIB follows Linux: IPv4 keeps appended routes beside the
first and removes the one a deletion names; IPv6 merges them into one
multipath route, and deleting a next hop removes only that next hop.

zebra-rs installs its static routes as `proto zebra` (`RTPROT_ZEBRA`,
11), so they are distinguishable from operator `proto static` routes,
which are always kernel routes. Consumers that classify kernel routes by
protocol now see zebra-rs statics as routing-daemon output: OVN learns
routes above `RTPROT_STATIC` from the VRF tables it watches, so a
zebra-rs static configured in such a VRF becomes an OVN `Learned_Route`
(as an FRR static, `proto 196`, does). Statics zebra-rs installed as
`proto static` before this release were skipped by OVN. Routes left by an earlier zebra-rs run (a
crash, or a stop without cleanup) are found at startup by protocol:
`proto zebra`, IS-IS and OSPF in any table, and BGP in VRF tables. Each
stays in place and keeps forwarding until its owner's fresh route
replaces it; whatever is not replaced is removed
`--leftover-sweep-time` seconds after startup (default 120; OSPF sweeps
its own once it has converged). Cleanup removes every leftover priority,
including floating backups and ECMP or blackhole paths, during both
replacement and sweeping. Main-table `proto bgp` routes are never
claimed, because another daemon may own them. Before this release
zebra-rs installed statics as `proto static`: on the first start after
upgrading, such a route is adopted when the static configuration
installs the same route (table, prefix and priority), and otherwise left
as an operator route. SRv6 routes (`seg6`/`seg6local` encapsulation)
under zebra-rs's protocol numbers are never ingested: their owners
reinstall them in place. An earlier run's that this run has not
reinstalled by the end of the grace period is removed.

## Kernel contract

* Local Type-2 advertisements correlate eligible local FDB rows with ARP/NDP.
  MAC-only, IPv4 and IPv6 bindings have separate NLRI keys and lifetimes.
  `EXT_LEARNED` state is never re-advertised as local state.
* Received Type-2 routes may carry the optional Label2 (the L3VNI under
  symmetric IRB, RFC 9135). It is accepted and re-advertised unchanged;
  zebra-rs does not yet originate it or install Type-2 host routes in VRFs.
* A remote MAC/IP route for a MAC learned locally is installed only if it
  outranks this speaker's own route, in FRR's order: a sticky MAC wins, a
  shared non-zero Ethernet Segment keeps the local path, then the higher
  MAC Mobility sequence number, then the lower VTEP address (RFC 7432
  §7.7, §15). A route it does not outrank is removed from the kernel
  state rather than overwriting the local FDB row, and is installed again
  if the local route is withdrawn. The same applies to an IP bound
  locally to any MAC: a local MAC/IP route carries the higher of its MAC's
  sequence number and the IP's highest remote one plus one, so an IP that
  moves here on a new MAC outranks its old binding (FRR's neighbor
  sequence numbers). As in FRR, a remote binding is installed as a NOARP
  neighbor the kernel will not let ARP override, so the PE an IP moved to
  learns it once the old PE withdraws. Sticky, default-gateway and router flags
  are read from the RFC 7432 MAC Mobility, Default Gateway and RFC 9161 ND
  communities.
* Remote Type-2 bindings install `EXT_LEARNED` / `NOARP` neighbors on the
  owning bridge, plus the remote MAC/VTEP FDB. Withdrawing one binding keeps
  the MAC when another NLRI still references it. Neighbor deletion checks
  ownership before removing an entry replaced by a local neighbor.
* The existing Type-3 path provides remote VTEP flood membership. Locally
  originated routes preserve the selected VTEP independently of the BGP
  session's source interface address, including a VTEP equal to the
  router-id. A next hop that is only the router-id fallback (no VXLAN local
  address and no `vtep-source`) is still rewritten to the session's local
  address.
* Imported Type-5 routes use the remote VTEP as gateway on the L3-VNI bridge,
  with RMAC FDB and neighbor state. IPv6 prefixes use an IPv4-mapped gateway
  and `onlink`, with corresponding IPv4 and mapped-IPv6 RMAC neighbors.
  Linux normalizes IPv6 metric zero to 1024. RMAC state remains
  until the last imported prefix using it is withdrawn. The bridge FDB
  holds one destination per MAC, so when several VTEPs advertise the same
  RMAC in an L3 VNI, traffic for all of their prefixes goes to one of them
  (FRR has the same limitation). When that VTEP is withdrawn, the entry
  moves to a remaining one. Give each VTEP a distinct RMAC.
* Bridge Type-5 state is reinstalled when the kernel drops it: on link up
  of the L3-VNI bridge or VXLAN device (admin-down deletes IPv4 routes
  without a notification), when its RMAC neighbor or FDB row is deleted
  while still needed (carrier loss, flushes), and when the VXLAN joins a
  bridge. A route the kernel rejects (for example while the bridge is
  down) is kept as desired state and installed on recovery. A route
  deleted by someone else is reinstalled, as FRR does for its own routes.
  Moving the L3-VNI VXLAN to another bridge moves the routes and RMAC
  neighbors with it and removes those left on the old bridge.
* Adopted fixed-VNI VXLAN ports retain their normal bridge encapsulation.
  VLAN-to-VNI tunnel mapping is applied only to metadata-mode VXLAN.
  Flat fixed-VNI bridges are supported; VLAN-aware fixed-VNI bridges have
  not been qualified by this change.
* Kernel-only underlay routes can resolve VTEP reachability, except through a
  default route. Protocol routes
  take precedence over their kernel shadows to retain transport metadata.
  VRF kernel routes observed before config adoption survive startup replay.

Bridge-based Type-5 installation is opt-in and currently targets a unicast VXLAN
nexthop with an IPv4 VTEP. Inner IPv4 and IPv6 are supported. Changing the
mode while routes are active does not replay those routes; configure it at
startup. Existing route installation remains the default when the option
is disabled. Validation does not qualify 500k routes, EVPN mobility,
multihoming or prefix ECMP.

## Validation

```bash
cargo fmt --all -- --check
cargo test --workspace --exclude bdd
cargo clippy --workspace --all-targets -- -D warnings
```

The self-contained [Linux namespace test](../tests/evpn-linux-kernel/README.md)
uses two zebra-rs speakers and Linux forwarding to check Type-2/3/5
exchange, IPv4/IPv6 switching and routing, ordinary static-blackhole
redistribution, binding withdrawal and shared-adjacency cleanup. It requires
no external routing software or application consuming kernel state.
[Recorded results](validation/evpn-linux-kernel.md): 38/38 checks.

The external OVN comparison lab uses two Kind hosts, two Arista cEOS leaves,
L2 VNI 1000 and L3 VNI 2000. Its acceptance checks cover Type-2/3/5 exchange,
IPv4/IPv6 kernel and OVN Southbound state, bidirectional switching/routing,
VXLAN packet captures, access-link withdrawal/restore, routed-subnet
withdrawal/restore, and routing-speaker restart. Functional results and their
scope are recorded in `docs/validation/ovn-ceos-kind.md`.
