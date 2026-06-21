# BGP EVPN BUM Tunnel Segmentation (RFC 9572) — Implementation Plan

Status: proposed (2026-06-20). Scope locked with Kunihiro:
**control-plane only** (defer ALL forwarding), **inter-region (RBR) first**,
first PR = **Phase 0+1** (PMSI Tunnel attribute hardening + Type 9/10/11
wire codec + round-trip unit tests).

Branch: `bgp-evpn-tunel-segmentation` (already created).

Status note: numbers below (PR counts, file lists, byte offsets) are
estimates to guide the work, not commitments. RFC field widths were
cross-checked against the RFC 9572 text (`.txt` rendering) — re-verify any
detail flagged "confirm on interop" against a real capture before relying
on it.

## Table of contents

1. What we are building
2. Standards basis — the load-bearing numbers
3. Reference implementations and what they tell us
4. **Linux kernel data-plane feasibility (the load-bearing question)**
5. Architecture overview
6. Packet codec design (`crates/bgp-packet`) — this PR
7. Control-plane design (`zebra-rs/src/bgp`) — later phases
8. YANG / config — later phases
9. Show / operational model — later phases
10. Phasing / PR plan
11. Validation strategy
12. Risks and open questions

---

## 1. What we are building

RFC 9572 ("Updates to EVPN Broadcast, Unknown Unicast, or Multicast (BUM)
Procedures", May 2024, updates RFC 7432) lets an EVPN segment the
**provider tunnel** that carries BUM traffic at **region / AS boundaries**
instead of building one end-to-end tunnel from ingress PE to every egress
PE. A *segmentation point* (an ASBR for inter-AS, a Regional Border Router
/ RBR for inter-region) terminates the upstream tunnel segment and
re-originates into the downstream one, rewriting the BGP next hop and the
PMSI Tunnel Attribute (PTA) for the local segment.

It adds three EVPN NLRI route types:

| Type | Name | Role |
|-----:|------|------|
| **9** | Per-Region I-PMSI A-D | Aggregates the inclusive BUM tunnel of all PEs in a region into one route across region boundaries |
| **10** | S-PMSI A-D | Selective (S,G)/(\*,G) tunnels (like SMET Type 6, but with an explicit provider tunnel in the PTA) |
| **11** | Leaf A-D | Explicit leaf discovery when the PTA's Leaf-Information-Required (L) flag is set |

zebra-rs is a PE/router. The natural roles are **ingress/egress PE** and
**RBR/ASBR segmentation point**. This plan delivers a correct, observable
**control plane** first and attaches the (kernel-limited) data plane behind
it — the same rhythm as the Flowspec, SR-Policy, BGP-LS, and EVPN-SRv6-L2
work.

### The foundation already exists

This is an *extension*, not a greenfield. The inclusive-multicast BUM spine
is already in tree:

| Capability | Where |
|---|---|
| EVPN NLRI codec (Types 1–5), nom-derive style | `crates/bgp-packet/src/attrs/nlri_evpn.rs` |
| **Type-3 IMET (inclusive multicast)** origination | `evpn_originate_imet()` @ `zebra-rs/src/bgp/route.rs` |
| **PMSI Tunnel attribute (path attr 22)** codec | `crates/bgp-packet/src/attrs/pmsi_tunnel.rs` |
| **VXLAN ingress replication (HER)** dataplane | `route_evpn_export_selected()` → `rib::Message::MdbAdd` → kernel zero-MAC FDB, via netlink |
| EVPN Loc-RIB / Adj-RIB, RD/RT auto-derivation | `route.rs` `LocalRibEvpnTable`; `adj_rib.rs` `AdjRibEvpnTable` |
| Type-5 (RFC 9136) full pipeline (pattern to mirror) | `evpn_originate_type5()` @ `route.rs` |

RFC 9572 reuses exactly this spine: it (a) aggregates the IMET inclusive
tunnel per-region (Type 9), (b) makes it selective (Type 10), and (c)
stitches it across boundaries (re-origination + Leaf A-D).

## 2. Standards basis — the load-bearing numbers

| Item | Value | Source |
|------|-------|--------|
| EVPN AFI / SAFI | L2VPN **25** / EVPN **70** | RFC 7432 |
| PMSI Tunnel Attribute | path attr **22**, optional-transitive | RFC 6514 §5 |
| PTA **L** (Leaf-Information-Required) flag | low-order bit of Flags, **0x01** | RFC 6514 §5 |
| Region ID in Type-9 NLRI | **8 octets**, encoded like an Extended Community, carried *inside the NLRI* | RFC 9572 §3.1 |

**New EVPN route-type NLRI formats** (RD-stripped key in brackets):

- **Type 9 — Per-Region I-PMSI A-D** (`RFC 9572 §3.1`), fixed **20 octets**:
  ```
  RD(8) | Ethernet Tag ID(4) | Region ID(8)
  ```
- **Type 10 — S-PMSI A-D** (`RFC 9572 §3.2`; "identical to the S-PMSI A-D
  route as defined in [RFC7117]" plus the Ethernet Tag ID and Originator's
  Addr Length fields), variable:
  ```
  RD(8) | Ethernet Tag ID(4)
       | Multicast Source Length(1, BITS) | Multicast Source(0/4/16)
       | Multicast Group  Length(1, BITS) | Multicast Group (0/4/16)
       | Originator's Addr Length(1, BITS) | Originator's Addr(4/16)
  ```
  Length fields are in **bits** (0 = wildcard `*`, 32 = IPv4, 128 = IPv6),
  matching the RFC 6514/7117 convention and the existing IMET parser's
  `addr_len == 32` test. *(Confirm on interop: the originator length unit
  is inferred from EVPN consistency, not stated as bits/octets in the
  diagram.)*
- **Type 11 — Leaf A-D** (`RFC 9572 §3.3`), variable:
  ```
  Route Key(variable) | Originator's Addr Length(1, BITS) | Originator's Addr(4/16)
  ```
  The **Route Key is the full NLRI of the triggering route** (a Type-9,
  Type-10, or IMET Type-3 NLRI, *including* its route-type and length
  octets — self-delimiting, so the codec reads type+len then `len` body
  octets to find where the Route Key ends and the Originator begins).

**PMSI Tunnel Types** (IANA "PMSI Tunnel Types" registry; the PTA's Tunnel
Type octet):

| # | Tunnel type | Kernel-realizable? (see §4) |
|--:|-------------|----|
| 0 | No tunnel information present | n/a |
| 1 | RSVP-TE P2MP LSP | ❌ no MPLS P2MP in Linux |
| 2 | mLDP P2MP LSP | ❌ no MPLS P2MP in Linux |
| 3 | PIM-SSM Tree | ⚠️ needs PIM + mroute |
| 4 | PIM-SM Tree | ⚠️ needs PIM + mroute |
| 5 | BIDIR-PIM Tree | ⚠️ needs PIM + mroute |
| **6** | **Ingress Replication** | ✅ VXLAN HER (already wired) |
| 7 | mLDP MP2MP LSP | ❌ no MPLS P2MP in Linux |
| 11 | BIER | ❌ not in mainline |

**Segmentation-specific attributes (consumed in Phase 3+, not the codec):**
- **Region ID Extended Community** for re-origination (RFC 9572 §6.2):
  Transitive 2-octet-AS EC sub-type `0x09`, Transitive 4-octet-AS EC
  sub-type `0x09`, or Transitive IPv4-address EC (area id in Global Admin).
- **Multicast Flags Extended Community** with the IANA *segmentation
  support* bit (RFC 9572 §8) — gates legacy-PE coexistence.
- **DF Election Extended Community** (RFC 8584) attached to a re-advertised
  Type-9 with the AC-DF bit cleared (RFC 9572 §5.3.1) so exactly one ASBR
  forwards into a downstream AS containing legacy PEs.
- **Leaf A-D auto-RT**: an IP-address-format RT with Global Admin = the
  re-originator's next hop and Local Admin = 0 (RFC 9572 §6.3) constrains
  Leaf A-D distribution back to the upstream RBR.

## 3. Reference implementations

- **FRR** implements EVPN Types 1–5 over VXLAN with head-end replication,
  but **does NOT implement RFC 9572** (no per-region I-PMSI / tunnel
  segmentation; `grep -ri "per-region\|EVPN.*segmentation"` in FRR is
  empty). As with SAFI-73 SR Policy, **FRR cannot be a wire-interop peer
  for Types 9/10/11** — the codec is the highest-risk surface and must be
  validated by round-trip tests + a captured/replayed UPDATE, not by FRR.
- **Juniper (MX) and Nokia (SR OS)** integrate EVPN BUM with MVPN/PMSI and
  are the realistic interop references (and the likely source of a pcap).
- **MVPN (RFC 6514) and VPLS (RFC 7117)** are the direct ancestors: Type-10
  S-PMSI and Type-11 Leaf A-D are the EVPN restatements of the MVPN
  S-PMSI/Leaf A-D routes, so the existing literature and any MVPN captures
  are directly informative for the codec.

## 4. Linux kernel data-plane feasibility (the load-bearing question)

**The control plane (all of §6–§9 below) has zero kernel dependency** —
route-type codecs, the PTA, region config, RBR/ASBR re-origination, and
Leaf A-D discovery are pure userspace BGP. zebra-rs can implement and
BGP/BDD-validate all of RFC 9572 regardless of kernel support.

**The data plane is where mainline Linux constrains us**, unevenly across
the provider-tunnel types RFC 9572 segments:

| P-tunnel type | Mainline Linux mechanism | Verdict |
|---|---|---|
| **Ingress Replication / VXLAN** | VXLAN netdev + bridge FDB all-zeros `dst` entries per VTEP (head-end replication); already wired via `MdbAdd` | ✅ **Native** — the only kernel-native P-tunnel |
| **PIM-SM/SSM/Bidir underlay** | `MRT`/`MRT6` mroute sockets + VXLAN `group` transport | ⚠️ kernel has mroute, but needs a PIM daemon zebra-rs lacks; underlay multicast must be provided externally |
| **mLDP / RSVP-TE P2MP (MPLS)** | MPLS dataplane is **unicast-only** — multipath = ECMP (one nexthop chosen), not replication; no P2MP/MP2MP label forwarding | ❌ **Hard blocker** → VPP / eBPF / ASIC |
| **BIER** | not in mainline | ❌ not available |
| **Segmentation gateway stitching** | VXLAN-IR↔VXLAN-IR is *approximable* with dual VXLAN netdevs on one bridge + `isolated`/split-horizon ports, but the DF / split-horizon correctness (§5.3.1) is not cleanly expressible | ⚠️ cleanest in VPP / eBPF |

This is **the same wall already documented for EVPN-SRv6-L2** (the kernel's
`seg6local` lacks `End.DT2U`/`End.DT2M`, so L2-over-SRv6 needs VPP/eBPF).
The honest posture, therefore:

- **Phases 0–5 (control plane): kernel-independent, fully implementable and
  BDD-validatable** over a netns route-reflector / two-AS topology with no
  forwarding required.
- **Phase 6 (data plane): scoped to the VXLAN Ingress-Replication subset on
  the kernel** (per-region IR aggregation at the gateway). MPLS-P2MP / BIER
  segmentation and a clean DF/split-horizon gateway are **deferred to a
  VPP/eBPF backend** — explicitly out of scope for the kernel dataplane,
  mirroring the SR-Policy and EVPN-SRv6-L2 deferrals.

## 5. Architecture overview

```
        ┌──────────────────────── crates/bgp-packet ───────────────────────────┐
 wire → │ nlri_evpn.rs: EvpnRoute += PerRegionImet(9) / SPmsi(10) / LeafAd(11)  │
        │ pmsi_tunnel.rs: PmsiTunnel.tunnel_type: u8 → PmsiTunnelType enum + L   │
        └──────────────────────────────────────────────────────────────────────┘
                                   │ parsed UpdatePacket
                                   ▼
        ┌──────────────────────── zebra-rs/src/bgp ─────────────────────────────┐
        │ route.rs: EvpnPrefix += PerRegionImet / SPmsi / LeafAd keys            │
        │   ingress/egress PE  : originate/import IMET as today                  │
        │   RBR/ASBR (Phase 3+): re-originate w/ next-hop + PTA rewrite,         │
        │                        Per-Region I-PMSI aggregation, Leaf A-D auto-RT │
        │ show bgp evpn route-type {…|per-region-imet|s-pmsi|leaf}  (Phase 2 ✓)  │
        └──────────────────────────────────────────────────────────────────────┘
                                   │ selected routes (Phase 6, kernel-limited)
                                   ▼
        ┌──────────── zebra-rs/src/rib + fib (deferred, VXLAN-IR only) ─────────┐
        │ per-region IR aggregation at the gateway (dual VXLAN on a bridge);     │
        │ MPLS-P2MP / BIER / clean DF stitching → VPP/eBPF backend (out of scope)│
        └──────────────────────────────────────────────────────────────────────┘
```

## 6. Packet codec design (`crates/bgp-packet`) — **this PR (Phase 0+1)**

### 6.1 Phase 0 — `pmsi_tunnel.rs` hardening

- Promote `PmsiTunnel.tunnel_type: u8` to a typed `PmsiTunnelType` enum
  (values 0–7, 11, `Unknown(u8)`) with `From<u8>`/`From<PmsiTunnelType> for
  u8` round-trips and a `Display`. Only `IngressReplication` (6) is acted on
  by the dataplane; the rest are carried for transit/interop.
- Add Leaf-Information-Required (**L**) flag helpers on the Flags octet
  (`leaf_info_required()` / `set_leaf_info_required()`, bit `0x01`,
  RFC 6514 §5). Needed by Phase 3 re-origination; landed now with the
  attribute it belongs to.
- Update the sole non-test constructor (`route.rs evpn_originate_imet`,
  `tunnel_type: 6` → `PmsiTunnelType::IngressReplication`).

### 6.2 Phase 1 — `nlri_evpn.rs` route-type codec

- `EvpnRouteType` += `PerRegionImet` (9), `SPmsiAd` (10), `LeafAd` (11) and
  the `From`/`Into<u8>` arms.
- `EvpnRoute` += three structs (mirroring `EvpnIpPrefix`'s id/rd shape):
  - `EvpnPerRegionImet { id, rd, ether_tag, region_id: [u8; 8] }`
  - `EvpnSPmsi { id, rd, ether_tag, src: Option<IpAddr>, grp: Option<IpAddr>, originator: IpAddr }`
  - `EvpnLeafAd { id, route_key: Vec<u8>, originator: IpAddr }`
- `EvpnPrefix` (RD-stripped RIB key) += `PerRegionImet`, `SPmsi`, `LeafAd`
  variants, **declared after `IpPrefix`** so the derived `Ord` keeps the
  route-type ordering 2 < 3 < 5 < 9 < 10 < 11. `route_type()` and
  `from_route()` extended; `Display` arms added (`[9]:…`, `[10]:…`,
  `[11]:…`).
- `parse_nlri` / `nlri_emit` arms for all three types. Source/group/
  originator lengths handled in **bits** via the existing `nlri_psize`
  (bits→bytes) helper; the Leaf A-D Route Key is treated as the
  self-delimiting embedded NLRI (`route_type(1) | length(1) | body(length)`)
  followed by the originator.
- Add-Path parity (leading 4-byte path id when `id != 0`), matching the
  existing Type-2/3/5 encoders.

### 6.3 Tests (this PR)

Round-trip `emit → parse_nlri` per new type, plus field-level emit asserts
(byte offsets), plus an `EvpnPrefix` ordering/`route_type()`/`Display`
test, mirroring the existing `evpn_emit_tests` / `evpn_prefix_tests`
modules. The codec is the highest-risk surface (no FRR interop peer), so
this is where the safety lives.

**Deliberately deferred out of this PR** (to keep it minimal and
reviewable): the Region ID / Multicast Flags / DF Election Extended
Communities — they are consumed only by Phase 3 re-origination, not by the
codec — and any RIB/Adj-RIB/show/origination wiring.

## 7. Control-plane design (later phases)

- **Phase 2 — RIB + Adj-RIB + show. DONE.** The receive-side drop guard in
  `route_evpn_update` was removed, so types 9/10/11 now flow through the same
  generic Adj-RIB-In → Loc-RIB → best-path → reflect path as the other EVPN
  types (the `LocalRibEvpnTable` / `AdjRibEvpnTable` are fully generic over
  `EvpnPrefix` — no per-variant RIB code). They carry no VXLAN dataplane
  action (`route_evpn_export_selected` no-ops). They render in `show bgp evpn`
  via `EvpnPrefix::Display`, and a new **`show bgp evpn route-type
  {macip|multicast|prefix|smet|per-region-imet|s-pmsi|leaf}`** filter was
  added (`/show/bgp/evpn/route-type` → `show_bgp_evpn`, keyword → route-type
  number via `evpn_route_type_filter`). Pinned by a `config/parse.rs`
  path/args test (the show-grammar gotcha) + a filter-vs-`route_type()`
  cross-check unit test. Command is `show bgp evpn route-type …` (not `l2vpn
  evpn`), matching the existing `show bgp evpn` grammar. **Note:** YANG `enum`
  bodies can't carry `ext:help` in this parser — keep enums bare (the
  `yang_load_tests` guard catches it; cargo/clippy don't). End-to-end
  receive→show with real routes is BDD-covered in Phase 3 (needs origination).
- **Phase 3 — inter-region (RBR, RFC 9572 §6) — first real milestone.**
  Sliced smallest-first:
  - **3a — segmentation-support signaling. DONE.** Added Bit 8 (`0x0080`,
    RFC bit numbering MSB-0 so `1<<7`) to the existing `EvpnMcastFlags` EC
    (with the all-clear "ignore" guard generalized so a segmentation-only EC
    survives), an instance `segmentation` knob mirroring `igmp_mld_proxy`
    (`router bgp afi-safi evpn segmentation`), and set the bit on originated
    IMET via the Multicast Flags EC. `show bgp evpn` renders it as
    `mcast-flags:…S` (added a `(0x06,0x09)` arm to `format_evpn_ecom_value`
    reusing the codec Display). Unit-tested (codec round-trip incl.
    segmentation-only + combined; `segmentation`-settable; show render) —
    matching how the twin `igmp-mld-proxy` feature shipped (no dedicated
    BDD). DF-Election EC is **§5.3.1 inter-AS only → Phase 4**, not needed
    here.
  - **3b — RBR re-origination (the meat). DONE.** Region = BGP neighbor-group
    (§6.1): `region-id <asn>` on a neighbor-group, resolved onto the peer
    (`Peer.region_id`) by `apply_inherited` and stashed on the received row
    (`BgpRib.ingress_region`). The §6.2 Region ID is the 8-octet Source-AS
    EC encoding (`region_id_from_asn`, shown as `AS:<n>`). When an in-region
    per-PE IMET arrives, the RBR re-originates one aggregate Type-9 per
    `(region, eth-tag)` (`evpn_reoriginate_per_region`) as an `Originated`
    row — so the advertise gate stamps next-hop-self (§6.3, next-hop-based,
    no S-NH-EC) — reusing the IMET's RT/encap and rewriting the PTA to an
    IR tunnel rooted at the RBR. The advertise gate adds two §6 suppressions:
    a region's Type-9 is never sent back into that region, and per-PE IMET
    is held at the boundary (ingress region ≠ egress region; non-region
    peers unaffected). 2-region BDD (`@bgp_evpn_segmentation`) + unit tests
    (encoding, `region-id`-settable). **Deferred follow-ups:** Type-9
    *withdrawal* when the last in-region IMET leaves; re-originating only on
    a changed aggregate (today every in-region IMET re-fires, idempotent);
    RR-based suppression BDD; S-PMSI (Type-10) aggregation.
  - **3c — Leaf A-D. DONE.** The RBR's re-originated Type-9 now carries the L
    (Leaf Information Required) flag, and its PMSI Tunnel attribute is built
    from the configured `bum-tunnel-type` (`imet_pmsi_tunnel`) — plain IR or an
    SR P2MP tree rooted at the RBR. A downstream node that receives a Type-9
    (or Type-10) with L=1 auto-derives the IP-address-format RT
    `<originator-next-hop>:0` and originates a Type-11 Leaf A-D
    (`evpn_segmentation_leaf_ad_on_receive`) keyed by the triggering NLRI
    (`evpn_leaf_ad_route_key`, generalized from the RFC 9574 AR path to any
    EVPN route type), reporting its own VTEP; the upstream consumes it to build
    the region's leaf set. The shared origination helper
    (`evpn_originate_leaf_ad`) is parameterized `ar_leaf: bool` — AR-typed Leaf
    PMSI for RFC 9574, plain IR PMSI for RFC 9572 segmentation. Withdrawal of
    the Type-9/10 pulls the Leaf A-D. `@bgp_evpn_segmentation` BDD extended
    with the region-B leaf answering and the RBR collecting the Leaf A-D; unit
    test pins the Type-9 route_key. **Deferred:** the upstream does not yet act
    on the collected leaf set (no replication-list dataplane — Phase 6); a node
    joins every soliciting upstream rather than a single chosen one.
- **Phase 4 — inter-AS (ASBR, RFC 9572 §5) + legacy coexistence.** ASBR
  becomes the root of the intra-AS segment; per-AS IMET stays AS-local,
  per-region I-PMSI crosses AS boundaries; DF Election EC (AC-DF cleared)
  picks one forwarding ASBR; the Multicast-Flags segmentation bit gates
  legacy-PE behavior. Sliced like Phase 3:
  - **4a — DF Election EC codec. DONE.** `DfElectionEc { df_alg, bitmap }` in
    `ext_com.rs` (RFC 8584 §2.2): EVPN high-type 0x06 / sub-type 0x06; `val[0]`
    low 5 bits = DF Alg (`ALG_DEFAULT`/`ALG_HRW`), high 3 = RSV; `val[1..3]` =
    16-bit Bitmap with AC-DF = Bit 1 (MSB-0) = `CAP_AC_DF` (0x4000); `val[3..6]`
    reserved. `is_evpn_df_election`/`as_df_election`, `From<DfElectionEc>`,
    `ac_df()`/`with_ac_df()`, `df-election:alg<N>[+ac-df]` Display, round-trip
    unit tests. No behavior change.
  - **4b — inter-AS ASBR re-origination.** ASBR re-originates the per-region
    I-PMSI across the AS boundary (eBGP) with next-hop-self; per-AS IMET held
    AS-local. Extends `evpn_reoriginate_per_region`; needs an AS-boundary
    config model decision (reuse `region-id` neighbor-group vs a new toggle).
  - **4c — DF election among ASBRs + legacy coexistence.** Attach the DF
    Election EC with AC-DF cleared to the re-advertised Type-9 so exactly one
    ASBR forwards into a downstream AS with legacy PEs; gate legacy behavior on
    the Multicast-Flags segmentation bit. End-to-end BDD.
- **Phase 5 (optional) — S-PMSI selective multicast (Type 10 + Leaf A-D)**
  end to end; ties to SMET (Type 6) if/when that lands.

## 8. YANG / config (later phases)

Extend `zebra-bgp-evpn.yang` (and a peer-group augmentation) with a
`region-id` leaf and a `segmentation` boundary toggle, plus per-EVI
inclusive/selective tunnel-type selection (defaulting to ingress
replication). Config callbacks mirror the existing `config_advertise_all_vni`
registration. Remember `cargo`/`clippy` do not validate YANG — the
`yang_load_tests` CI guard does.

## 9. Show / operational model (later phases)

Hand-rolled Rust→(text|JSON) `show` registered in `show.rs`, one block per
route type: Per-Region I-PMSI (RD, eth-tag, region, PTA tunnel type/leaf
flag), S-PMSI ((S,G), PTA), Leaf A-D (route-key summary, originator).

## 10. Phasing / PR plan

Small PRs on `bgp-evpn-tunel-segmentation`; `cargo fmt` + workspace clippy
before each; CI is the source of truth (don't run bdd locally — full suite
on push, not targeted filters).

- **PR1 — Phase 0+1: PTA hardening + Type 9/10/11 codec + unit tests.**
  No behavior change; decode/encode + round-trip tests only. *(this PR)*
- **PR2 — Phase 2: RIB/Adj-RIB plumbing + `show` + parse() show tests. DONE.**
  Removed the receive drop guard; added `show bgp evpn route-type <kw>` filter.
- **PR3a — Phase 3a: segmentation-support signaling. DONE** (#1507).
- **PR3b — Phase 3b: inter-region RBR re-origination. DONE (this PR).**
  neighbor-group `region-id`, `Peer.region_id` / `BgpRib.ingress_region`,
  cross-region IMET suppression, Type-9 aggregation/re-origination with
  next-hop-self, `AS:<n>` region rendering, `@bgp_evpn_segmentation` BDD,
  and the EVPN-segmentation book chapter.
- **PR3c — Phase 3c: Leaf A-D. DONE (this PR).** L flag on the re-originated
  Type-9, BUM-tunnel-typed PTA, `evpn_segmentation_leaf_ad_on_receive` →
  Type-11 with auto-RT `<nh>:0`, generalized `evpn_leaf_ad_route_key` /
  `evpn_originate_leaf_ad(ar_leaf)`, Type-9/10 withdrawal pulls the Leaf A-D,
  `@bgp_evpn_segmentation` leaf scenarios. Remaining 3b follow-ups
  (change-gated re-origination, S-PMSI aggregation) and leaf-set dataplane
  stay deferred.
- **PR4a — Phase 4a: DF Election EC codec (RFC 8584). DONE (this PR).**
  `DfElectionEc` in `ext_com.rs` + AC-DF accessors + Display + round-trip
  tests. No behavior change.
- **PR4b — Phase 4b: inter-AS ASBR re-origination** (per-region I-PMSI across
  the AS boundary, next-hop-self; per-AS IMET AS-local).
- **PR4c — Phase 4c: DF election among ASBRs (AC-DF cleared) + legacy
  coexistence gating + BDD.**
- **PR5 (optional) — Phase 5: S-PMSI selective multicast + BDD.**
- **PR6 (later, re-confirm direction) — Phase 6: VXLAN-IR aggregation
  dataplane only;** MPLS-P2MP / BIER / clean-DF gateway → VPP/eBPF backend.

## 11. Validation strategy

- **Unit / round-trip tests** in `bgp-packet` for every new NLRI and the
  PTA enum/flag — the highest-risk surface, and FRR can't peer with it.
- **BDD** for the receive → re-originate → show pipeline in CI (control
  plane only; no dataplane needed to prove the BGP exchange). Each feature
  tears down its namespaces/daemons explicitly.
- **Wire interop:** FRR is *not* usable (no RFC 9572). Validate against a
  **Juniper/Nokia** speaker or a **captured EVPN Type-9/10/11 UPDATE pcap**
  replayed into the parser; diff our emitted bytes against the reference
  once origination lands. MVPN S-PMSI/Leaf captures inform Types 10/11.

## 12. Risks and open questions

- **No FRR interop peer** for Types 9/10/11 — the biggest risk. Mitigate
  with pcap fixtures + a Juniper/Nokia capture; get one real RFC-9572
  capture early.
- **Originator's Addr Length unit (bits vs octets)** in Type-10/11 — modeled
  as bits for EVPN consistency; confirm against a real capture before the
  origination phase.
- **Leaf A-D Route Key recursion** — the embedded NLRI must be parsed
  self-delimited (type+len) to split Route Key from Originator; a malformed
  embedded length must fail the parse cleanly, not over-read.
- **Kernel dataplane ceiling** — only VXLAN-IR is kernel-native; MPLS-P2MP /
  BIER / clean-DF gateway need VPP/eBPF. The control plane must not assume a
  tunnel type the local dataplane can't realize when *originating* (it may
  still relay any tunnel type as a segmentation transit).
- **DF election / split-horizon at the gateway** — correctness is hard on a
  Linux bridge; design it with Phase 6, not before.
- **Region = peer-group** modeling — confirm the config ergonomics map
  cleanly onto zebra-rs's neighbor-group machinery in Phase 3.
