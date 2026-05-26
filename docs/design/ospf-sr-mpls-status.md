# OSPF SR-MPLS status

Snapshot of OSPFv2 + OSPFv3 SR-MPLS as of `main` ≈ commit `3ac9f422`
(PR #896 merged). Captures what is wire-complete, where the seams
are, and which follow-ups are worth picking from in a future session.

Same standing guidance applies as elsewhere in `docs/design/`:
recommend the smallest meaningful slice with the main tradeoff, ship
one branch / one PR at a time, don't queue follow-up files before
review.

## Status: wire-complete, not FRR-runtime-validated

OSPFv2 and OSPFv3 both originate, ingest, install, and surface every
SR sub-TLV class the consumer crates currently model:

| Capability                | v2 (RFC 7684 + RFC 8665) | v3 (RFC 8362 + RFC 8666) |
| ---                       | ---                      | ---                      |
| Router Information / SR-info advertise | Opaque RI LSA (type 4)  | E-Router-LSA SR-info TLVs (LS-ID 0) |
| Prefix-SID originate      | OpaqueAreaExtPrefix      | E-Intra-Area-Prefix-LSA  |
| Adj-SID originate (P2P)   | OpaqueAreaExtLink + AdjSid | E-Router-LSA Router-Link TLV + AdjSid |
| LAN-Adj-SID originate     | OpaqueAreaExtLink + LanAdjSid | E-Router-LSA Router-Link TLV + LanAdjSid |
| Remote SRGB / SRLB ingest | `Lsdb::update_lsa`       | `Lsdb::update_lsa_v3`    |
| Remote Prefix-SID populate to RIB | `add_prefix_sids`        | `add_prefix_sids_v3`     |
| Self Prefix-SID pop ILM   | `add_self_prefix_sids_to_ilm` | `add_self_prefix_sids_to_ilm_v3` |
| Self Adj-SID / LAN-Adj-SID pop ILM | `add_self_adj_sids_to_ilm`    | `add_self_adj_sids_to_ilm_v3` |
| `show ... segment-routing` CLI | `show_ospf_segment_routing`   | `show_ospfv3_segment_routing` (local + remote, peer SRGB/SRLB headers) |

The v3 series of stacked PRs that landed this work is the fastest
path to learning the file layout:

- **#838–#840** — YANG schema mirror (IS-IS shape, no `block` knob,
  v3-only `srv6` deferred).
- **Phase A (v2)**: #841 populate Prefix-SID into RIB, #842 install
  MPLS state, #843 self Prefix-SID pop ILM.
- **Phase B (v2)**: #844 Adj-SID parser, #845 storage, #846 P2P
  originate, #847 self Adj-SID ILM, #848 FRR-interop ExStart loop
  fix (RFC 5250 §2.1 Opaque-O-bit gating), #849 FRR Cisco-experimental
  Remote-Itf-Addr sub-TLV decode, #850 SRLB pool, #851 LAN-Adj-SID
  originate, #852 LAN-Adj-SID ILM.
- **Phase D (v3)**: #853 E-LSA scaffolding, #854 Router-Link TLV +
  Adj-SID, #856 Intra-Area-Prefix TLV + Prefix-SID, #858 v3 Prefix-SID
  originate, #862 v3 P2P Adj-SID originate, #865 v3 LAN-Adj-SID
  originate, #868 v3 Prefix-SID populate, #871 v3 Prefix-SID install,
  #874 v3 self Prefix-SID pop ILM, #878 v3 self Adj-SID / LAN-Adj-SID
  pop ILM.
- **Phase E (v3 show + SR-info round-trip)**: #880 local v3 show,
  #884 remote Prefix-SIDs in v3 show, #887 SR-Algorithm / SID-Label
  Range / SR Local Block wire codec, #890 originate, #893 ingest into
  `Lsdb::label_map`, #896 show consumes `label_map`.

## Known seams

These are not bugs; they are the "I chose to keep the PR small" calls
worth remembering before extending.

### Hardcoded SRGB / SRLB
`zebra-rs/src/ospf/srmpls.rs`:
```
pub(super) const SRGB_START: u32 = 16000;
pub(super) const SRGB_RANGE: u32 = 2001;
pub(super) const SRLB_START: u32 = 15000;
pub(super) const SRLB_RANGE: u32 = 1000;
```
IS-IS has YANG knobs for these; OSPF does not yet. Both v2's
`router_info_lsa_build` and v3's `e_router_v3_sr_info_lsa_build` read
the constants directly. Configurable SRGB / SRLB is the natural next
step (mirror the IS-IS shape).

### v3 SR-info LSA placement is by convention, not by RFC fiat
`SR_INFO_LSID = 0` reserves LS-ID 0 for the SR-info-only
E-Router-LSA. Per-link E-Router-LSAs key by `ifindex` (Linux ifindex
≥ 1, so no collision). Foreign implementations may put the same TLVs
on any E-Router-LSA — our ingest path (`Lsdb<Ospfv3>::update_lsa_v3`)
scans every E-Router-LSA from a peer, so that interop works. Our
originator only ever emits the dedicated LS-ID 0 LSA.

### `OSPFV3_SUB_TLV_SID_LABEL = 5`
The inner SID/Label sub-TLV type number nested inside SID/Label
Range / SR Local Block TLVs is a best-effort reading of the IANA
"OSPFv3 Extended-LSA Sub-TLVs" registry. Verify against a real peer
if FRR interop matters; round-trip self-tests pass.

### `Eq` on `Ospfv3ELsaBody`
Body only derives `PartialEq` because `Ospfv3SubTlv::Unknown` carries
`Vec<u8>`. Anything that wants hashable / Ord-eq LSA bodies will need
to either skip Unknown or wrap it.

### Self-originated v3 SR-info ingest
`Lsdb<Ospfv3>::update_lsa_v3` only fires on the
`packet_v3::insert_received_v3` path (i.e., from-peer flooding).
Self-originated LSAs go through `install_originated` directly, so
`label_map[self.router_id]` stays empty. The v3 show path reads
local SRGB/SRLB from the `srmpls.rs` constants and is fine; if a
future feature wants a uniform `label_map`-keyed lookup, add a call
to `update_lsa_v3` from `e_router_v3_sr_info_lsa_originate` before
`install_originated`.

### `SpfRouteV3.sid` resolution depends on peer SR-info LSA arrival
`add_prefix_sids_v3` skips remote prefixes whose `adv_router` has no
`label_map` entry yet. Index-form Prefix-SIDs that arrive before the
peer's SR-info LSA stay unresolved until SPF re-runs after the
SR-info LSA arrives. SPF re-runs on any LSDB change in the same area,
so this self-heals — but a packet capture during convergence can show
the gap.

## Follow-ups, smallest first

### 1. Configurable SRGB / SRLB (YANG)
Mirror IS-IS's shape. Today the `segment-routing/mpls` container is
present-only (presence boolean). Add `srgb { start, range }` and
`srlb { start, range }` children, route them through to
`Ospf<V>::sr_block` state, and have the LSA builders read from there
instead of the `srmpls.rs` constants. Small, well-bounded, exercises
both v2 and v3 originate paths.

### 2. FRR interop validation pass for v3 SR-MPLS
End-to-end on a multi-router topology: bring up FRR↔zebra-rs OSPFv3
with SR-MPLS, verify Prefix-SID / Adj-SID / LAN-Adj-SID labels
forward; capture the LFIB on both ends. Update the FRR-validated
memory note when done. Defensive but high-signal — we have several
"best-effort" type numbers and conventions that this would lock in.

### 3. Inter-area Prefix-SID
RFC 8665 §4 (v2 Ext-Prefix Range) / RFC 8666 §4 (v3 E-Inter-Area-Prefix-LSA
with PrefixSid sub-TLV). Requires plumbing the SR sub-TLV through the
ABR's Summary-LSA build path and the consumer's inter-area route
lookup. Medium scope; needs ABR support in both versions to be
testable, which is already in place.

### 4. TI-LFA / FRR fast-reroute for OSPF
IS-IS has TI-LFA (memory: `zebra-rs-isis-lsp-fragmentation` and
related). OSPF does not. Largest scope on this list — backup-path
SPF (RFC 7490 LFA / RFC 8102 P-space/Q-space), micro-loop avoidance,
repair-label-stack plumbing through the RIB. Would span several PRs.

### 5. OSPFv3 IPsec authentication (RFC 4552)
Locked-plan Phase 7 item. Linux XFRM-based; v3 has no in-band
authentication of its own. Touches the v3 socket setup and possibly
the NFSM if SA establishment can fail. Out of scope for SR-MPLS but
listed for completeness when the Phase 7 work resumes.
