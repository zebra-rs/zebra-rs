# OSPFv3 SRv6 (RFC 9513) — implementation plan

Locked 2026-06-12. Brings OSPFv3 to parity with the IS-IS SRv6 stack:
locator origination, End/End.X SIDs, SRv6 TI-LFA repairs with
NEXT-C-SID carrier compression. The IS-IS implementation is the
blueprint throughout — every dataplane lesson it validated applies
verbatim, because the FIB/RIB layers are shared:

- **End.X nh6 must be the neighbor's GLOBAL address** (PR #1361):
  Linux's seg6local End.X re-resolves nh6 with iif = the packet's
  ingress interface, so a link-local nh6 blackholes. OSPFv3 learns
  neighbor addresses from Link-LSAs (link-local) — the global must
  come from the neighbor's Intra-Area-Prefix/Link-LSA prefixes that
  fall on the shared link.
- **uA installs classic /128; the NEXT-CSID flavor goes on the
  LIB twin** (`block:function` prefix entry, PR #1364) and on the uN
  prefix entry only.
- **Repairs are SRH insertion (H.Insert), never H.Encap** — transit
  End/End.X repair segments have no decap terminator (memory of the
  original IS-IS validation; `EncapType::HInsert` plumbing shared).
- **BDD must include the promoted-backup scenario from day one** —
  link-down scenarios never exercise SRH forwarding (PR #1361's bug
  survived two "passing" features that way).

## Wire model (RFC 9513)

| Item | Registry | Value |
|---|---|---|
| SRv6 Capabilities TLV | OSPF RI TLVs | 20 |
| SRv6 Locator LSA | OSPFv3 LSA Function Codes | 42 (area scope, U=1 → ls_type 0xA02A) |
| SRv6 Locator TLV | new: OSPFv3 SRv6 Locator LSA TLVs | 1 |
| SRv6 End SID sub-TLV | new: OSPFv3 SRv6 Locator LSA Sub-TLVs | 1 |
| SRv6 SID Structure (locator home) | OSPFv3 SRv6 Locator LSA Sub-TLVs | 10 |
| SRv6 SID Structure (E-LSA home) | OSPFv3 Extended-LSA Sub-TLVs | 30 |
| SRv6 End.X SID sub-TLV | OSPFv3 Extended-LSA Sub-TLVs | 31 |
| SRv6 LAN End.X SID sub-TLV | OSPFv3 Extended-LSA Sub-TLVs | 32 |

In-house conventions carried over:

- zebra-rs has no standalone Router Information LSA for v3; RI-style
  TLVs (SR-Algorithm, SID/Label Range, SRLB, FAD) ride a dedicated
  E-Router-LSA instance (`SR_INFO_LSID`). The SRv6 Capabilities TLV
  (type 20 — collision-free with the in-house Ext-TLV numbers) joins
  that LSA rather than introducing an RI LSA.
- Endpoint behaviors stay raw `u16` in the codec (the IANA "SRv6
  Endpoint Behaviors" registry is protocol-neutral); the daemon maps
  them through `isis_packet::Behavior`, which already models the full
  registry including the NEXT-C-SID variants.

## Phases

1. **Codec** (this PR): all RFC 9513 wire types in
   `crates/ospf-packet/src/v3.rs` — SRv6 Capabilities Ext-TLV, the
   SRv6 Locator LSA (own TLV/sub-TLV registries: Locator TLV,
   End SID sub-TLV, SID Structure 10), and the Extended-LSA sub-TLVs
   (SID Structure 30, End.X SID 31, LAN End.X SID 32, with nested
   structure sub-TLVs). Parse/emit round-trip tests; LSDB/show accept
   the new ls_type without choking.
2. **Config + locator origination**: `router ospfv3 segment-routing
   srv6 locator <name>` (YANG mirror of IS-IS), watch the RIB locator
   registry, originate the SRv6 Locator LSA (End SID = locator base,
   behavior End/uN by locator mode) + SRv6 Capabilities; install the
   End/uN SID via `SidAdd` (registry, kernel install, show — all
   shared with IS-IS).
3. **End.X origination**: one End.X/uA per Full neighbor from the
   ELIB function pool (share `isis::srv6::ElibPool` or lift it to a
   common home); advertise sub-TLV 31/32 on the Router-Link TLV;
   install with global nh6 + drift re-install + LIB twin for uSID
   locators (ports of `reconcile_endx_sid` / `reconcile_endx_lib_sid`).
4. **Receive side**: parse neighbors' Locator LSAs in the LSDB
   rebuild, feed locator prefixes into the v3 route calculation
   (route_type/algorithm/metric semantics per §7.1), and collect
   per-neighbor End/End.X SIDs + structures (the v3 sibling of
   `srv6_end_map`).
5. **TI-LFA SRv6**: v3 sibling of `build_repair_path_srv6` — resolve
   `spf::RepairPath` segments to SRv6 SIDs from the maps of phase 4,
   reuse the NEXT-C-SID carrier packer (lift `pack_carriers` out of
   `isis::tilfa` into a shared module), install as `HInsert` repairs.
6. **BDD + show**: `ospfv3_tilfa_srv6.feature` mirroring
   `isis_tilfa_srv6.feature` (eight routers, e1/e2 LAN hosts if BGP
   service traffic is included, uSID + classic variants as needed),
   including the promoted-backup forwarding scenario from the start;
   `show ospfv3` SRv6 blocks.

## Deferred / out of scope

- Algorithm ≠ 0 locators (Flex-Algo SRv6) — locator TLV carries the
  algorithm field; consumption beyond algo 0 deferred.
- Anycast locators (AC-bit prefix option, also allocated by RFC 9513).
- SRv6 in `router ospf` (v2) — SRv6 is v6-native; not applicable.
- Locator LSA sub-TLVs 2–5 (forwarding address, route tag, prefix
  source) — parsed as Unknown, not consumed.
