# BGP Link-State (BGP-LS, AFI 16388 / SAFI 71) — Design & Implementation Plan

Status: Phase 2 (BGP-LS Attribute codec) in progress. Phase 1 (NLRI codec) merged in #1064.

RFC 9552 (obsoletes RFC 7752).

## Overview

This document captures the design and phased implementation plan for BGP
Link-State (BGP-LS) support in zebra-rs.

BGP-LS distributes the IGP link-state topology and traffic-engineering
information into BGP, typically toward a controller / PCE / topology collector.
It uses **AFI 16388** with **SAFI 71** (non-VPN); **SAFI 72** (BGP-LS-VPN) is
intentionally deferred.

There are two roles:

- **Producer (exporter):** translate the local IGP link-state database into
  BGP-LS NLRI + the BGP-LS Attribute and advertise it to BGP peers. This is the
  headline goal. **The first (and, for now, only) IGP integration is IS-IS;**
  OSPFv2/OSPFv3 (Protocol-IDs 3/6) come later — the codec and RIB are
  protocol-agnostic, so only an additional producer is needed for OSPF.
- **Consumer (collector / reflector):** receive BGP-LS NLRI from peers, store it
  in a Loc-RIB, run best-path, and reflect/propagate it. Built first because it
  is testable in isolation (against a peer or captured packets), matching how
  the flowspec and SR-policy series were sequenced.

The design mirrors the existing BGP AFI/SAFI implementations (flowspec, EVPN,
SR-policy): an exact-match Loc-RIB keyed by the NLRI, a new path attribute, MP
capability negotiation, and an `afi-safi link-state` config knob.

## Architecture: how the IS-IS LSDB reaches BGP

zebra-rs runs each protocol (BGP, IS-IS, OSPF) and the central RIB as separate
tokio tasks communicating over channels — there is **no shared mutable state**
between modules, and the IS-IS LSDB (`Isis::lsdb: Levels<Lsdb>`) is never
accessed from outside the IS-IS task.

The BGP-LS **producer therefore lives inside the IS-IS task**. IS-IS already
knows how to parse its own TLVs; it translates them into `bgp_packet::BgpLsNlri`
(+ BGP-LS Attribute) objects and **pushes add/withdraw messages to BGP over a
channel**, mirroring the existing route-redistribution flow
(`isis/rib.rs` → `rib_client.send(...)`). BGP never parses IS-IS TLVs. This
keeps layering clean and avoids snapshot/locking concerns.

The producer reacts to the IS-IS event bus (`Message::Lsdb`, `Message::SpfDone`)
and re-walks the affected level's LSDB using the same iteration the
`show isis database` path uses (`isis/show.rs`). Per RFC 9552 §5.2, any
add/remove/modify of a TLV requires withdrawing the old NLRI first; the producer
diffs its previously-advertised object set per source node and emits explicit
withdrawals.

## Wire encoding (RFC 9552)

### Link-State NLRI (carried in MP_REACH_NLRI / MP_UNREACH_NLRI)

```
+-------------------------------+
| NLRI Type (2)                 |   1=Node, 2=Link, 3=IPv4 Prefix, 4=IPv6 Prefix
+-------------------------------+
| Total NLRI Length (2)         |
+-------------------------------+
| Protocol-ID (1)               |   1=IS-IS L1, 2=IS-IS L2, 3=OSPFv2,
+-------------------------------+   4=Direct, 5=Static, 6=OSPFv3
| Identifier (8)                |   BGP-LS Instance-ID (0 if single instance)
+-------------------------------+
| Descriptors (TLVs)            |
+-------------------------------+
```

- **Node NLRI:** Local Node Descriptors (TLV 256).
- **Link NLRI:** Local (256) + Remote (257) Node Descriptors + Link Descriptors.
- **Prefix NLRI:** Local (256) Node Descriptors + Prefix Descriptors.

Node Descriptor sub-TLVs: AS (512), BGP-LS Identifier (513), OSPF Area-ID (514),
IGP Router-ID (515), BGP Router-ID (516), Member-AS (517).
Link Descriptor TLVs: Link Local/Remote Identifiers (258), IPv4 interface (259),
IPv4 neighbor (260), IPv6 interface (261), IPv6 neighbor (262), Multi-Topology
ID (263). Prefix Descriptor TLVs: Multi-Topology ID (263), OSPF Route Type
(264), IP Reachability (265).

Unknown/odd-length codepoints are preserved verbatim and re-emitted so a
collector/reflector round-trips and propagates them unchanged.

### BGP-LS Attribute (BGP path attribute type 29)

An optional, non-transitive attribute carrying Node (1024–1031), Link
(1088–1098), and Prefix (1152–1158) attribute TLVs (plus the SR codepoints from
RFC 9085). Modeled as a preserved TLV list (`BgpLsAttr` / `BgpLsAttrTlv`) so
unknown TLVs round-trip; typed construction/decoding is layered on by the
producer and show path in later phases.

## Phased plan (branch per phase, smallest reviewable PR first)

1. **NLRI codec** *(merged #1064)* — `crates/bgp-packet/src/attrs/nlri_bgpls.rs`:
   `BgpLsNlri` (Node/Link/IPv4Prefix/IPv6Prefix) + descriptor TLVs/sub-TLVs,
   `LsProtocolId`, parse + `bgpls_nlri_emit`, round-trip tests. Derives
   `Ord`/`Hash` for exact-match RIB keying. No behavior change.
2. **BGP-LS Attribute codec** *(this PR)* — `attrs/bgpls_attr.rs`,
   `AttrType::BgpLsAttr=29`. Optional non-transitive (type 29); value is a
   preserved TLV list (`BgpLsAttr` / `BgpLsAttrTlv`) so unknown codepoints
   round-trip. `AttrEmitter` impl picks (extended) length automatically. The
   `Attr`-enum / `parse_attr` / `BgpAttr` wiring lands in Phase 3 alongside
   negotiation (a type-29 attribute is only received once BGP-LS is negotiated).
3. **AFI/SAFI plumbing** — `Afi::LinkState=16388` / `Safi::LinkState=71` enum
   variants (+ exhaustive-match fallout across show/route/config), MP_REACH /
   MP_UNREACH `LinkState` branches, `Attr::BgpLs` wiring, MP capability
   negotiation (`bgp/cap.rs`), YANG `enum link-state` in `zebra-afi-safi.yang`,
   `Args::afi_safi()` (`"link-state"`).
4. **Receive-side RIB** — `LocalRib.bgpls` exact-match table (like flowspec),
   `route_bgpls_update` / `route_bgpls_withdraw`, dispatch in `route_from_peer`,
   iBGP / route-reflector propagation.
5. **Show** — `show bgp link-state` + summary label / RIB counts in `bgp/show.rs`.
6. **Producer bridge (IS-IS → BGP)** — new channel; on `Lsdb`/`SpfDone` walk
   the level's LSDB; map TLV 22/222 → Link NLRI, TLV 135/235/236/237 → Prefix
   NLRI, fragment-0 Router-Capability/Hostname/TE-Router-ID → Node NLRI;
   Protocol-ID from `Level::digit()`; two-way connectivity check before
   advertising Link NLRIs; withdraw-old-on-change.
7. **Producer attribute / SR-TE enrichment** — link attrs (admin-group 1088,
   bandwidths 1089–1091, TE metric 1092, IGP metric 1095, Adj-SID 1099, SRv6
   End.X), node attrs (SR Capabilities 1034 / SRGB, SR Algorithm 1035).

## Deferred

- BGP-LS-VPN (SAFI 72) and the 8-octet Route Distinguisher NLRI prefix.
- OSPFv2/OSPFv3 producers (Protocol-IDs 3/6).
- SR-TE / SRv6 attribute completeness beyond what IS-IS already models.
