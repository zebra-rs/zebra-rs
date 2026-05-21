# BGP ↔ IS-IS SR-MPLS Flex-Algorithm integration — design plan

Status as of 2026-05-21. Tracks the design and PR sequence for steering
BGP-learned traffic into IS-IS Flex-Algorithm paths in zebra-rs.

Companion document: [`flex-algo-roadmap.md`](flex-algo-roadmap.md) tracks the
IS-IS-only remaining work; this document covers everything BGP-side plus the
glue layer (resolver + FIB).

## Goal

A BGP-learned route (L3VPN, EVPN, internet unicast, …) carrying a
**Color extended community** is forwarded over the IS-IS Flex-Algorithm
whose ID is bound to that color in local config. The outer transport label
is the **Per-Algo Prefix-SID** advertised by the BGP next-hop on that algo;
the inner label is whatever the service AFI/SAFI requires.

## Out of scope

- PCEP and any PCE-driven path computation.
- BGP-LS distribution of Flex-Algo state (deferred — see Phase 6).
- SRv6 dataplane (parse-and-store only — full SRv6 services are a separate
  track).
- Controller-originated SR Policies (SAFI 73) — only the receiver side of the
  Color community is required for v1.

---

## Inventory snapshot (2026-05-21)

| Area | State | Pointer |
|---|---|---|
| IS-IS FAD sub-TLV 26 + constraints (parse/encode/emit) | ✅ | `crates/isis-packet/src/sub/cap.rs`, `isis/lsp.rs` |
| Per-interface per-algo Prefix-SID config | ✅ | `isis/link.rs` |
| Peer FAD / per-link ASLA / per-algo Prefix-SID caches | ✅ | `isis/flex_algo.rs`, `isis/lsdb.rs` |
| SR Algorithms sub-TLV, SRGB, algo-0 LFIB | ✅ | `ospf/srmpls.rs`, `rib/segment_routing/` |
| BGP recursive next-hop resolution via IGP | ✅ | `rib/resolve.rs` |
| **Per-algorithm SPF & per-algo LFIB install** | ❌ | covered by `flex-algo-roadmap.md` |
| BGP attr 23 (Tunnel-Encap), attr 40 (Prefix-SID) | ❌ | `crates/bgp-packet/src/attrs/attr.rs` falls into `Unknown(u8)` |
| Color extended community `0x03 0x0b` | ❌ | `crates/bgp-packet/src/attrs/ext_com.rs` parses as opaque |
| Color/algo-aware next-hop resolution | ❌ | `rib/resolve.rs` ignores algorithm |
| Per-algo RIB sub-type / colored nexthop | ❌ | `rib/entry.rs::RibSubType` has only `Default` |

---

## Phase 0 — IS-IS Flex-Algo dataplane (prerequisite)

Without per-algo SPF and per-algo LFIB install, BGP has nothing to steer into.
This phase belongs to the IS-IS track; **see
[`flex-algo-roadmap.md`](flex-algo-roadmap.md) for the canonical breakdown**.
Summary of what BGP integration depends on:

1. Per-algorithm SPF (`spf/calc.rs` parameterised by `algo: u8` + FAD filter).
2. Per-algo Prefix-SID resolution against peer-advertised SIDs (already
   cached in `Isis::peer_algo_sid`).
3. LFIB install: `(incoming algo-N label) → (algo-N nexthop, swap)`.
4. RIB demux: `RibSubType::FlexAlgo(u8)` so per-algo IP routes coexist with
   default routes. Recommendation for v1: **MPLS-only** — skip per-algo IP
   RIB until a use case beyond BGP steering appears.

**No new files in BGP for this phase.**

## Phase 1 — BGP attribute / community plumbing

Pure wire-format work in `crates/bgp-packet/`. No semantic behaviour yet, so
each item is independently shippable and individually testable via
round-trip codec tests.

### 1.1 Prefix-SID attribute (attr 40) — RFC 8669, RFC 9252

- Add `PathAttr::PrefixSid(Vec<PrefixSidTlv>)` to the attribute enum.
- TLVs:
  - **Type 1 — Label-Index** (7 octets: reserved/flags/label-index).
  - **Type 3 — Originator-SRGB** (variable, list of SRGB ranges).
  - **Type 5 — SRv6 L3 Service** (parse-and-store; deferred semantics).
  - **Type 6 — SRv6 L2 Service** (parse-and-store).
- Round-trip tests under `crates/bgp-packet/tests/`.
- Extend the `dump-bgp` corpus with captured UPDATEs containing attr 40.

### 1.2 Tunnel Encapsulation attribute (attr 23) — RFC 9012

- Add `PathAttr::TunnelEncap(Vec<TunnelTlv>)`.
- Tunnel-Type registry (minimum):
  - **15 — SR Policy** (RFC 9256)
  - **13 — MPLS-in-GRE** (commonly co-deployed)
- Sub-TLVs (minimum):
  - 4 — Color
  - 6 — Preference
  - 12 — Remote-Endpoint
  - 13 — Binding-SID
  - 128 — Segment List (with weight + segment sub-sub-TLVs)
  - 129 — Policy-Name, 130 — Policy-Candidate-Path-Name

### 1.3 Color extended community

- In `crates/bgp-packet/src/attrs/ext_com.rs`, decode opaque type
  `0x03 0x0b` as `ExtCommunity::Color { co_bits: u2, reserved: u14, color: u32 }`.
- CO-bits per draft-ietf-idr-bgp-ct §3.2.1; v1 only treats `00`, the others
  parse but are not acted on.
- Encode path: route-map `set color` populates a Color ext-comm with CO=00.

### 1.4 Capability 73 (SR Policy SAFI) — deferred

Required only if Phase 6 adds SAFI 73. Not part of v1.

**Files (new):** `crates/bgp-packet/src/attrs/prefix_sid.rs`,
`crates/bgp-packet/src/attrs/tunnel_encap.rs`. **Edits:**
`crates/bgp-packet/src/attrs/{attr.rs,ext_com.rs,mod.rs}`.

## Phase 2 — Policy + ingest/originate behaviour

Wires the Phase-1 codec into BGP semantics.

1. **Route-map predicates / actions**:
   - `match color <N>`
   - `set color <N>` (append to ext-comm list)
   - `set prefix-sid label-index <N>` (sets attr 40 TLV 1 on origination)
2. **Receive path** (`bgp/packet/update.rs` consumer):
   - When attr 40 TLV 1 present → stash `label_index` on the path attrs
     stored with the adj-RIB-in entry; egress PE uses it to compute the
     service label against its own SRGB.
   - When Color ext-comm present → stash `Vec<(co_bits, color)>` on the path.
3. **Originate / readvertise path**:
   - On local-originate or redistribute, optionally attach attr 40
     Label-Index (configurable) and a Color list (from route-map).
   - `next-hop-self` semantics already exist in `bgp/nexthop` — Color/SID
     pass through unchanged.
4. **Color → algo binding table** (BGP-local config):

   ```yang
   container color-policy {
     list color {
       key color-value;
       leaf color-value     { type uint32; }
       leaf flex-algorithm  { type uint8 { range "128..255"; } }
       leaf strict          { type boolean; default true; }
     }
   }
   ```

   Multiple colors may map to the same algo (RFC 9256 §2.5 fallback
   ordering). IS-IS does not learn about BGP color — the mapping is BGP-local.

## Phase 3 — Color-aware next-hop resolution (the integration spine)

1. **Resolver API change** in `rib/resolve.rs`:
   ```rust
   fn resolve(nh: IpAddr, color: Option<Color>)
       -> Option<ResolvedNexthop { ifindex, labels: Vec<Label>, algo: u8 }>;
   ```
2. **Algorithm**:
   - `color = None` → today's path: algo-0 lookup, no SR label push (or
     algo-0 SR label if SR-only mode is configured).
   - `color = Some(c)` → consult color→algo table → look up per-algo entry
     for `nh` in the IS-IS algo-N route table (Phase 0) → return
     `outer_label = peer_algo_sid[(nh_router, algo)]` and the algo-N egress
     nexthop. Miss → entry stays invalid (RFC 9256 §8.8 strict default; the
     `strict` knob in §2.4 lets the operator opt into fallback later).
3. **Re-resolve on IGP churn**: Phase-0 SPF must publish per-algo route
   change events that BGP NHT subscribes to. Reuse the existing nexthop
   tracking notifier — add an `(algo, prefix)` axis to the event.
4. **Label stacking** for service AFI/SAFIs (L3VPN, EVPN, labeled unicast):
   FIB nexthop becomes `[outer = algo-N Prefix-SID, inner = service label]`.

## Phase 4 — FIB programming

1. Extend `fib/netlink/handle.rs` to push 2-label MPLS stacks
   (`MPLS_IPTUNNEL_DST` already supports a label list).
2. Add an integration fixture under `tests/` that brings up a minimal 3-node
   IS-IS topology with two FADs and verifies kernel LFIB + IP-MPLS encap
   entries for a BGP route with a Color community.
3. Per-route observability: `show ip bgp <prefix>` should expose
   `Color: 100 -> Algo: 128 -> Outer label: 16128`.

## Phase 5 — CLI, YANG, observability

1. YANG additions under `/router/bgp/`:
   - `color-policy/color/flex-algorithm` (see Phase 2.4)
   - `neighbor/.../send-prefix-sid`, `send-tunnel-encap`
2. CLI verbs: `set color`, `match color`, `show ip bgp color N`,
   `show ip bgp policy`.
3. Tracing spans (`tracing::debug_span!("bgp.nht.color")`) for resolver
   misses — Color resolution failures are otherwise silent.

## Phase 6 — *(Optional, deferable)* BGP-LS Flex-Algo advertisement

If zebra-rs ever needs to feed a controller, add SAFI 71/72 plus the FAD
descriptors from RFC 9551/9552. **Not required** for the BGP-steers-into-
Flex-Algo use case; recommend deferring until a concrete consumer exists.

---

## Suggested PR sequence

Following project convention (one branch per feature):

| # | Branch | Phase | Independently shippable? |
|---|---|---|---|
| 1 | `isis-flex-algo-spf` | 0.1–0.2 | ✅ IS-IS standalone benefit |
| 2 | `isis-flex-algo-lfib` | 0.3–0.4 | ✅ IS-IS standalone benefit |
| 3 | `bgp-attr-prefix-sid` | 1.1 | ✅ pure codec |
| 4 | `bgp-attr-tunnel-encap` | 1.2 | ✅ pure codec |
| 5 | `bgp-extcomm-color` | 1.3 | ✅ pure codec |
| 6 | `bgp-color-policy` | 2 | needs PR 5 |
| 7 | `bgp-color-nht` | 3 | needs PRs 2 + 6 |
| 8 | `bgp-flex-algo-fib` | 4 | needs PR 7 |
| 9 | `bgp-flex-algo-yang` | 5 | needs PR 6 |

PRs 1–2 are independently shippable IS-IS features. PRs 3–5 are independently
shippable BGP plumbing (no semantics). PRs 6–8 are the integration spine.
PR 9 lands the user-facing surface.

---

## Open questions

1. **Per-algo IP RIB or MPLS-only?** MPLS-only is cleanest — algo-N gives you
   labels and BGP resolution picks them up. Per-algo IP RIB is only useful
   if we want `ping` per algo. **Recommend MPLS-only for v1.**
2. **Color fallback policy.** RFC 9256 allows C-flag/O-flag fallback. Start
   strict (drop on miss), add fallback in a follow-up.
3. **SRv6 L3 service TLV (RFC 9252).** Parse-and-store now so the attribute
   layer doesn't churn when SRv6 services land. Semantics: deferred.
4. **CO-bits semantics** (draft-ietf-idr-bgp-ct). Implement bits `00` only
   initially; `01`/`10`/`11` (any-transport / SR-aware) can wait.
5. **Color binding scope.** Per-VRF or global? Recommend global default with
   per-VRF override — matches the staging model introduced in `Bgp::vrfs`
   (PRs #663/#665).

---

## RFCs & internet-drafts

### Segment Routing core

- **RFC 8402** — Segment Routing Architecture
- **RFC 8660** — SR-MPLS data plane
- **RFC 8661** — SR-MPLS interworking with LDP
- **RFC 9256** — SR Policy architecture

### IS-IS extensions

- **RFC 5305 / RFC 5308** — IS-IS extended reach / IPv6 reach (baseline)
- **RFC 7794** — IS-IS Prefix Attributes (extended IP reach flags)
- **RFC 7981** — IS-IS Router Capability TLV 242
- **RFC 8491** — Signaling MSD in IS-IS
- **RFC 8667** — IS-IS extensions for SR-MPLS (Prefix-SID, Adj-SID,
  SR-Capabilities, SRGB, SRLB, SR-Algorithms sub-TLV)
- **RFC 9479** — IS-IS Application-Specific Link Attributes (ASLA) — required
  for the per-application link attrs used by Flex-Algo
- **RFC 9350** — IGP Flexible Algorithm (FAD sub-TLV, advertisement rules,
  FAD election, Per-Algo Prefix-SID)
- **RFC 7308** — Extended Administrative Groups (affinity bits used by FAD
  include/exclude)
- **RFC 4203** — SRLG advertisement (referenced by Flex-Algo Exclude-SRLG
  sub-TLV)
- *(useful)* `draft-ietf-lsr-flex-algo-bw-con` — Flex-Algo bandwidth
  constraint sub-TLV
- *(useful)* `draft-ietf-lsr-flex-algo-srlg-exclude` — SRLG exclude
  clarifications

### BGP attribute & community machinery

- **RFC 4271** — BGP-4 (baseline)
- **RFC 4360 / RFC 7153** — BGP Extended Communities & IANA registry (where
  Color lives, type `0x03 0x0b`)
- **RFC 8669** — Segment Routing Prefix-SID attribute (attr 40; Label-Index
  TLV, Originator-SRGB TLV)
- **RFC 9012** — Tunnel Encapsulation attribute (attr 23); defines **Color**
  extended community (§4.3), Remote-Endpoint, Binding-SID, Tunnel-Type
  registry
- **RFC 9252** — BGP SRv6 Services (Prefix-SID SRv6 L3/L2 service TLVs) —
  parse-only relevance in v1
- *(in-progress)* `draft-ietf-idr-segment-routing-te-policy` — Advertising
  SR Policies in BGP (SAFI 73). Not strictly required for color-into-Flex-
  Algo, but the canonical wire format for SR Policy.
- *(in-progress)* `draft-ietf-idr-bgp-ct` — BGP Classful Transport Planes /
  CO-bits semantics on the Color community
- *(in-progress)* `draft-ietf-idr-bgp-color-extcomm` — clarifications to the
  Color extended community

### Service-layer references (consumers of the steering)

- **RFC 4364** — BGP/MPLS IP VPNs
- **RFC 4760** — Multiprotocol BGP (MP-BGP)
- **RFC 7432** — BGP MPLS-Based EVPN
- **RFC 8277** — Using BGP to bind MPLS labels to address prefixes (Labeled
  Unicast)
- **RFC 9136** — IP Prefix Advertisement in EVPN (RT-5) — common
  color-steered NLRI

### BGP-LS (Phase 6, optional)

- **RFC 9552** — BGP-LS distribution of link-state and TE info (replaces
  RFC 7752)
- **RFC 9551** — BGP-LS extensions for Flex-Algo (FAD descriptor
  distribution)
- **RFC 9085** — BGP-LS extensions for SR

### Operational / YANG

- **RFC 9020** — YANG model for SR
- **RFC 9587** — YANG model for SR Policy
- *(useful)* `draft-ietf-idr-bgp-model` — BGP YANG
