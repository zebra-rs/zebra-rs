# EVPN VPWS (E-Line over SRv6)

zebra-rs implements **EVPN VPWS** (Virtual Private Wire Service, RFC
8214) over an SRv6 data plane: a point-to-point **E-Line** that
cross-connects one local attachment circuit (AC) to one remote PE's AC
as a transparent wire — no MAC learning, no FDB, no flooding. The two
CEs behave as if joined by a cable: they share subnets and resolve each
other by ARP straight through the service.

Each side advertises a **per-EVI Ethernet A-D route (Type-1)** whose
Ethernet Tag is its *local* VPWS service instance id, carrying an
**SRv6 End.DX2 L2-Service Prefix-SID** (RFC 9252 §6.3) carved from the
BGP SRv6 locator. Importing the remote's Type-1 — matched by Ethernet
Tag == `remote-service-id` within the shared EVI — binds the remote SID
as the AC's cross-connect target. Forwarding runs in the
[eBPF data plane](ch-16-00-ebpf.md): the AC's ingress encapsulates every
frame (any EtherType)
MAC-in-SRv6 toward the remote SID, and the local End.DX2 decap emits
received frames raw on the same AC.

The RD is auto-derived as `router-id:evi`, the route-target as
`AS:evi`; the ESI is all-zero (single-homed) in this phase.

## Configuration

A VPWS service lives under the EVPN address family:

```
set router bgp global as 65001
set router bgp global router-id 10.0.0.1
set router bgp segment-routing srv6 locator LOC1
set router bgp afi-safi evpn vpws eline1 evi 100
set router bgp afi-safi evpn vpws eline1 local-service-id 101
set router bgp afi-safi evpn vpws eline1 remote-service-id 102
set router bgp afi-safi evpn vpws eline1 interface ce1
```

* `evi` scopes the auto-derived RD and RT; both ends must share it.
* `local-service-id` is advertised as our Type-1's Ethernet Tag; the
  remote end configures the same value as its `remote-service-id`
  (and vice versa — the ids cross).
* `interface` names the attachment circuit (the CE-facing port).
* The service's End.DX2 SID is carved dynamically from the BGP SRv6
  locator; no manual SID configuration.

The neighbor must negotiate the L2VPN/EVPN family
(`afi-safi evpn enabled true`).

### MTU signalling (RFC 8214 §3.1)

```
set router bgp afi-safi evpn vpws eline1 mtu 1500
```

Every VPWS Type-1 carries the **Layer-2 Attributes extended community**
(P bit set — single-homed primary) with the configured L2 MTU (0 /
unset = no check). When both ends signal non-zero MTUs that differ, the
remote is **not** bound — the service shows `mtu-mismatch` with the
offending remote MTU until the ends agree.

### VLAN-scoped services (End.DX2V)

```
set router bgp afi-safi evpn vpws eline2 evi 200
set router bgp afi-safi evpn vpws eline2 local-service-id 201
set router bgp afi-safi evpn vpws eline2 remote-service-id 202
set router bgp afi-safi evpn vpws eline2 interface ce1
set router bgp afi-safi evpn vpws eline2 vlan 30
```

`vlan` scopes the AC to one 802.1Q VID (RFC 8214 VLAN-based E-Line):
only tagged frames with that VID enter the cross-connect — the tag
crosses the service transparently — and the local SID becomes
**End.DX2V** (RFC 8986 §4.10), demuxing return traffic by inner VID
over the EVI's VLAN table. Tagged and untagged services can share the
same AC port: VID-scoped entries match first, everything else rides
the whole-port service.

> **Operational note:** VLAN offloads must be **off** on the CE side of
> the AC (`ethtool -K <if> txvlan off rxvlan off`). An offloaded tag
> travels as skb metadata, never in the packet bytes — and XDP, which
> classifies on bytes, cannot demux the VID. This is the standard
> requirement for any XDP VLAN path.

## Show command

```
> show bgp evpn vpws
VPWS service: eline1
  EVI: 100
  Service ID: local 101, remote 102
  Interface: ce1
  Local SID (End.DX2): fcbb:bbbb:1:40::
  Remote SID: fcbb:bbbb:2:40::
  State: up
```

`json` is supported. The state progresses `partial-config` (mandatory
leaves missing) → `pending` (config complete, no router-id / locator
yet) → `advertised` (Type-1 originated, remote not matched) →
`up` (remote SID bound to the AC), with `mtu-mismatch` reported when a
matching remote is rejected by the MTU check.

## Reconciliation

The service re-syncs — withdraw + re-originate + re-derive the AC
binding from the EVPN Loc-RIB — on any leaf change, router-id rebind,
and locator (re)resolution. The Loc-RIB rescan means ordering does not
matter: a remote Type-1 that arrived *before* the service was
configured (or re-pointed) is found without waiting for a route churn.

## Scope

Single-homed only (all-zero ESI): no multihoming, DF election, or
primary/backup signalling yet — the L2-Attributes P/B bits are fixed at
P=1/B=0. Forwarding requires the [eBPF data plane](ch-16-00-ebpf.md)
(`system ebpf enabled`); the kernel has no End.DX2/DX2V seg6local action, so
these SIDs are never installed via netlink.
