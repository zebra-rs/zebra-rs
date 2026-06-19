# BGP EVPN BUM Tunnel Segmentation (RFC 9572)

zebra-rs implements the control plane for **EVPN BUM tunnel segmentation**
as specified in RFC 9572 (*Updates to EVPN Broadcast, Unknown Unicast, or
Multicast (BUM) Procedures*). Segmentation lets the provider tunnel that
carries BUM traffic be **split at region or AS boundaries** instead of
building one end-to-end tunnel from the ingress PE to every egress PE. A
*segmentation point* — a Regional Border Router (RBR) for inter-region, or
an ASBR for inter-AS — terminates the upstream tunnel segment and
re-originates into the downstream one.

RFC 9572 adds three EVPN route types to do this:

| Type | Name | Role |
|---|---|---|
| **9** | Per-Region I-PMSI A-D | Aggregates the inclusive BUM tunnel of all PEs in a region into one route across the region boundary |
| **10** | S-PMSI A-D | Selective `(S,G)` / `(*,G)` tunnels |
| **11** | Leaf A-D | Explicit leaf discovery when the PMSI Tunnel attribute's L flag is set |

> **Scope — control plane first.** This is, by design, a **control-plane**
> feature: the route-type codecs, the Multicast Flags / region encodings,
> and the RBR re-origination procedures are pure BGP and have no kernel
> dependency. On the data plane, only **VXLAN ingress replication** is
> native to the Linux kernel; MPLS P2MP (mLDP / RSVP-TE) and BIER tunnel
> segmentation require a VPP or eBPF data plane and are out of scope for the
> kernel path. See the [introduction](ch-00-00-introduction.md) for the
> overall EVPN data-plane model.

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

> **Note** — the Designated-Forwarder Election Extended Community (RFC 8584)
> is required only for **inter-AS** segmentation with legacy PEs
> (RFC 9572 §5.3.1); it is not used on the inter-region (RBR) path.

## Verification

* `show bgp evpn route-type per-region-imet` on an egress PE lists the
  aggregated Type-9 route advertised by each RBR, with the RBR's address as
  the BGP next hop and the region's `AS:<n>` Region ID.
* `show bgp evpn` on the RBR shows the per-PE Type-3 routes it received from
  the local region (which it does **not** re-advertise across the boundary)
  alongside the single Type-9 it originates.
* The `mcast-flags:S` tag on a peer's Type-3 routes confirms that peer
  advertises segmentation support.
