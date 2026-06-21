# BGP EVPN BUM Tunnel Segmentation (RFC 9572)

zebra-rs implements **EVPN BUM tunnel segmentation** as specified in
RFC 9572 (*Updates to EVPN Broadcast, Unknown Unicast, or Multicast (BUM)
Procedures*). Segmentation lets the provider tunnel that carries BUM traffic
be **split at region or AS boundaries** instead of building one end-to-end
tunnel from the ingress PE to every egress PE. A *segmentation point* — a
Regional Border Router (RBR) for inter-region, or an ASBR for inter-AS —
terminates the upstream tunnel segment and re-originates into the downstream
one.

RFC 9572 adds three EVPN route types to do this:

| Type | Name | Role |
|---|---|---|
| **9** | Per-Region I-PMSI A-D | Aggregates the inclusive BUM tunnel of all PEs in a region into one route across the region boundary |
| **10** | S-PMSI A-D | Selective `(S,G)` / `(*,G)` tunnels |
| **11** | Leaf A-D | Explicit leaf discovery when the PMSI Tunnel attribute's L flag is set |

The full control plane is implemented — both **inter-region** (RBR, §6) and
**inter-AS** (ASBR, §5): per-region aggregation, Leaf A-D discovery, the
Designated-Forwarder election among redundant segmentation points, legacy-PE
coexistence, and the selective (S-PMSI) variant.

> **Data plane.** Segmentation is independent of the BUM tunnel encapsulation.
> The kernel-native path is **VXLAN ingress replication**. For an SRv6
> underlay, zebra-rs also drives an **RFC 9524 SR P2MP replication tree** via
> the `tc-evpn-replicate` eBPF offload (`bum-tunnel-type srv6-p2mp`, see [the
> data-plane section](#the-data-plane-sr-p2mp-replication-offload)) — a
> segmentation gateway re-floods cross-region BUM over that tree. MPLS P2MP
> (mLDP / RSVP-TE) and BIER remain out of scope (no kernel- or eBPF-feasible
> path). See the [introduction](ch-00-00-introduction.md) for the overall EVPN
> data-plane model.

## Advertising segmentation support

A PE tells its peers (and any RBR) that it supports the RFC 9572
procedures by setting **bit 8 of the EVPN Multicast Flags Extended
Community** (RFC 9572 §8) on every Type-3 (Inclusive Multicast / IMET)
route it originates. This is opt-in, under the `evpn` address family:

```
set router bgp afi-safi evpn advertise-all-vni true
set router bgp afi-safi evpn segmentation true
```

* `segmentation` defaults to `false`. When set, the Multicast Flags EC
  (with the segmentation-support bit) rides every locally originated IMET
  route. Toggling it re-originates all IMET routes so the bit is added or
  removed in place.
* It composes with `igmp-mld-proxy` (RFC 9251): the same Multicast Flags EC
  carries the IGMP-proxy, MLD-proxy, and segmentation-support bits
  independently.

The receiving peer renders the capability in `show bgp evpn` as a
`mcast-flags:` tag with one letter per bit — `I` (IGMP proxy), `M` (MLD
proxy), `S` (segmentation support):

```
Route Distinguisher: 10.0.0.1:10
 *>  [3]:[0]:[32]:[10.0.0.1]
                     10.0.0.1
                     RT:65001:10 ET:8 mcast-flags:S
```

## Inspecting the segmentation route types

`show bgp evpn` lists every EVPN route type, including the RFC 9572 types,
with their prefix forms:

| Type | `show bgp evpn` prefix form |
|---|---|
| 9 — Per-Region I-PMSI A-D | `[9]:[EthTag]:[RegionID]` |
| 10 — S-PMSI A-D | `[10]:[EthTag]:[Src]:[Grp]:[Orig]` |
| 11 — Leaf A-D | `[11]:[RouteKey]:[Orig]` |

To narrow the table to one route type, use the **`route-type`** filter:

```
show bgp evpn route-type per-region-imet
show bgp evpn route-type s-pmsi
show bgp evpn route-type leaf
```

The keyword set is `macip` (2), `multicast` (3), `prefix` (5), `smet` (6),
`per-region-imet` (9), `s-pmsi` (10), and `leaf` (11). With no keyword,
`show bgp evpn` shows all types.

## Inter-region segmentation (RBR)

For inter-region segmentation (RFC 9572 §6) a **region is defined as a BGP
peer-group** — it is an operator grouping, not derived from the IGP. A
Regional Border Router (RBR) sits on the boundary between two regions, each
modelled as a peer-group carrying a **region ID**:

```
set router bgp neighbor-group region-a region-id 65001
set router bgp neighbor-group region-b region-id 65002
```

The region ID is carried inside the Type-9 NLRI as an 8-octet,
Extended-Community-formatted value (RFC 9572 §6.2). The AS-number form is a
Transitive Two-Octet AS-specific EC of sub-type `0x09` (Source AS) — for
example region `65001` encodes as `00:09:fd:e9:00:00:00:00`, rendered as
`AS:65001`.

At the boundary, the RBR does **not** propagate per-PE IMET (Type-3) routes
across the region boundary. Instead it **aggregates** all the in-region
PEs' IMET routes into a single **Per-Region I-PMSI A-D (Type-9)** route,
advertised into the other region(s) with:

* the **BGP next hop changed to the RBR itself** (RFC 9572 §6.3 —
  next-hop-based, no Segmented-Next-Hop EC), and
* the originating region's **Region ID** in the NLRI.

An ingress PE in another region receives the Type-9 route and treats the
RBR's next hop as a proxy leaf for that whole region — it floods BUM toward
the RBR, which re-replicates into its own region. Where multiple RBRs front
the same region, each advertises the same Region ID and the downstream
selects one best path, so exactly one RBR forwards.

### Leaf A-D discovery

When the re-originated Type-9 (or Type-10) carries the **L
(Leaf-Information-Required) flag** in its PMSI Tunnel attribute, each
downstream node answers with a **Leaf A-D (Type-11)** route, keyed by the
triggering NLRI and reporting its own VTEP. This lets the segmentation point
learn the leaf set of the region it fronts. zebra-rs sets the L flag on the
re-originated Type-9 and originates the Leaf A-D automatically; the route is
scoped back to the originator with an IP-address-format Route Target
(`<originator-next-hop>:0`, RFC 9572 §6.3).

```
show bgp evpn route-type leaf
```

renders Leaf A-D routes as `[11]:[rt<route-key-type>/<N>B]:[<originator>]` —
for example `[11]:[rt9/30B]:[192.168.0.3]` is a leaf reporting itself in
response to a Per-Region I-PMSI (route-type 9).

## Inter-AS segmentation (ASBR)

Inter-AS segmentation (RFC 9572 §5) reuses the same machinery with
**`region = AS`**: set the `region-id` to each bordered AS number on the
**eBGP** neighbor-groups of the ASBR. An ASBR then aggregates its AS's per-PE
IMET into a Per-Region I-PMSI (Type-9) re-originated across the AS boundary
with next-hop-self and an `AS_PATH` of the local AS, holding the per-AS per-PE
IMET AS-local — exactly as the RBR does inter-region.

### DF election among redundant ASBRs

When several ASBRs border the same downstream AS, RFC 9572 §5.3.1 elects a
single **Designated Forwarder** so a downstream AS containing legacy PEs sees
no duplicated BUM. zebra-rs attaches a **DF Election Extended Community**
(RFC 8584) with the **AC-DF bit cleared** to the re-originated Type-9, and runs
the RFC 7432 §8.5 modulus election over the candidate ASBRs (every node
advertising that region's Type-9). `show bgp evpn` annotates the elected DF and
whether this node is it:

```
                    DF-election (modulus): DF=192.168.0.2 [candidates: 192.168.0.2 192.168.0.4] (this node is DF, forwards)
```

A standby ASBR shows `(standby)` and drops that region from its forwarding, so
only the DF delivers into it.

### Legacy-PE coexistence

A PE that does not set the segmentation-support bit (above) is a **legacy PE**.
A segmentation point notes when a region contains one — `show bgp evpn`
appends `(legacy PEs present)` to the DF-election line — which is the condition
under which the DF election is required.

## Selective multicast (S-PMSI)

Where the inclusive Type-9 carries *all* BUM for a region, a **selective
S-PMSI A-D (Type-10)** carries a specific `(S,G)` / `(*,G)` flow over its own
provider tunnel. With both `igmp-mld-proxy` and `segmentation` enabled, a PE
that snoops a local membership originates a Type-10 alongside the Type-6 SMET —
the difference being that the S-PMSI carries a **PMSI Tunnel attribute** (the
selective tunnel, rooted at the PE) while the SMET carries only receiver
interest. An RBR re-roots an in-region S-PMSI at itself toward the other
regions, the selective counterpart of the Type-9 aggregation:

```
show bgp evpn route-type s-pmsi
```

```
 *>  [10]:[0]:[*]:[239.1.1.1]:[192.168.0.1]      # a PE's selective tunnel
 *>  [10]:[0]:[*]:[239.1.1.1]:[192.168.0.2]      # re-rooted at the RBR
```

## The data plane: SR P2MP replication offload

For an SRv6 underlay, set `bum-tunnel-type srv6-p2mp` under the `evpn` family.
A segmentation gateway then re-floods cross-region BUM over an **RFC 9524 SR
P2MP replication tree** rooted at itself, toward the leaves it is the elected
DF for — forwarded by the `tc-evpn-replicate` eBPF offload (the kernel has no
native SR replication or `End.DT2M` L2 decap). The interfaces the offload
attaches to come from a per-instance topology block:

```
set router bgp afi-safi evpn bum-tunnel-type srv6-p2mp
set router bgp afi-safi evpn sr-p2mp-dataplane overlay-interface <bridge-port>
set router bgp afi-safi evpn sr-p2mp-dataplane underlay-interface <sr-nic>
set router bgp afi-safi evpn sr-p2mp-dataplane bridge-interface <leaf-flood-port>
set router bgp afi-safi evpn sr-p2mp-dataplane next-hop-mac <aa:bb:cc:dd:ee:ff>
```

The BGP control plane resolves each leaf VTEP to the `End.DT2M` SID it
advertised, forms a replication segment, and spawns + feeds two offload
children: an **ingress** classifier (`End.Replicate` fan-out + `End.DT2M`
decap) and an **encap** classifier (root `H.Encaps` of a bare BUM frame). With
the offload binary absent the control plane still signals — nothing forwards.

## Verification

* `show bgp evpn route-type per-region-imet` on an egress PE lists the
  aggregated Type-9 route advertised by each RBR, with the RBR's address as
  the BGP next hop and the region's `AS:<n>` Region ID.
* `show bgp evpn` on the RBR shows the per-PE Type-3 routes it received from
  the local region (which it does **not** re-advertise across the boundary)
  alongside the single Type-9 it originates.
* The `mcast-flags:S` tag on a peer's Type-3 routes confirms that peer
  advertises segmentation support.
