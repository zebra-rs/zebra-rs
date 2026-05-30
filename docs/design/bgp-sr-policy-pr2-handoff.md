# BGP SR Policy — PR2 handoff (typed Tunnel-Type-15 sub-TLVs)

Status: **DONE — retained as historical reference.** This started as the PR2
(typed sub-TLV) handoff; the whole SR Policy feature has since been
implemented and merged. It captures the authoritative wire layouts (verified
against RFC 9830 / RFC 9831 and the IANA registries) and supplements
[`bgp-sr-policy-plan.md`](bgp-sr-policy-plan.md) §5.3. Where it and the code
disagree, **the code is authoritative** — one byte-layout error below has
been corrected in place (see the Name sub-TLV note).

Implemented across these merged PRs (see [`bgp-sr-policy-plan.md`](bgp-sr-policy-plan.md)):
\#1055 SAFI+NLRI codec · #1063 typed Tunnel-Type-15 sub-TLVs (this doc's PR2)
· #1065 consumer DB + RFC 9256 §2.9 selection + show · #1066 SRv6 dataplane
(End.B6.Encaps) · #1068 SR-MPLS dataplane (BSID ILM) · #1069 automated
steering · #1072 originator · #1075 route-reflector pass-through. The typed
codec landed in `crates/bgp-packet/src/attrs/srpolicy.rs`.

## Scope (locked with Kunihiro)

PR2 = **SRv6-first subset**, decode-focused (with emit for round-trip tests):

- Typed view over a Tunnel-Type-15 TLV's sub-TLVs.
- Policy-level sub-TLVs: Preference (12), Binding SID (13), SRv6 Binding SID
  (20), ENLP (14), Priority (15), Segment List (128), Policy Name (130),
  Candidate Path Name (129).
- Segment List inner: Weight (9), Segment Type A (1, SR-MPLS label),
  Segment Type B (13, SRv6 SID).
- **Deferred to a follow-up:** Segment Types C–K (3–8, 14–16). They decode
  into `Segment::Unknown` (bytes preserved) for now.

Remote Endpoint (6) is a generic RFC 9012 sub-TLV, not SR-Policy-specific —
leave it opaque (it is not in the SR-Policy IANA sub-registry).

## What is already in tree (do not redo)

- `Safi::SrTePolicy = 73`, `SrPolicyNlri` codec, `MpReachAttr/MpUnreachAttr::SrPolicy`
  — PR1 (`crates/bgp-packet/src/attrs/nlri_srpolicy.rs`).
- **Tunnel Encap attr (type 23) is fully wired already:**
  - `attrs/attr.rs`: `AttrType::TunnelEncap = 23`, the `Attr::TunnelEncap(TunnelEncap)`
    variant, and `attr.rs:404` does `bgp_attr.tunnel_encap = Some(v)`.
  - `bgp_attr.rs:52`: `pub tunnel_encap: Option<TunnelEncap>`.
  - So a received UPDATE with attr 23 already lands in `bgp_attr.tunnel_encap`
    with **opaque** sub-TLVs. PR2 only adds the *typed view* on top.
- `attrs/tunnel_encap.rs` (315 lines) — the opaque framing + tests:
  ```rust
  pub struct TunnelEncap { pub tunnels: Vec<TunnelTlv> }
  pub struct TunnelTlv { pub tunnel_type: u16, pub sub_tlvs: Vec<TunnelSubTlv> }
  pub struct TunnelSubTlv { pub typ: u8, pub value: Vec<u8> }
  ```
  `parse_be` already handles the **sub-TLV length-width rule** (1 octet for
  type < 128, 2 octets for type ≥ 128 — RFC 9012 §3.1) and the tunnel TLV
  framing (2-octet type, 2-octet length). The typed layer should be built
  **on top of `TunnelSubTlv`** (parse the opaque `value` of each sub-TLV),
  exactly as `tunnel_encap.rs`'s doc-comment anticipates. Keep `TunnelEncap`
  storing opaque sub-TLVs so unknown ones round-trip for reflectors.

## Authoritative wire layouts (verified 2026-05-30)

Sub-TLV length-width rule: **type ≤ 127 → 1-octet Length; type ≥ 128 →
2-octet Length** (already implemented in `parse_sub_tlvs`).

### Policy-level sub-TLVs (direct children of Tunnel-Type-15)

| Type | Name | Length | Fields (in order, octets) |
|-----:|------|-------:|---------------------------|
| 12 | Preference | 6 | Flags(1) · RESERVED(1) · Preference(4) |
| 13 | Binding SID | 2 / 6 / 18 | Flags(1) · RESERVED(1) · BSID(0 \| 4 SR-MPLS \| 16 SRv6) |
| 20 | SRv6 Binding SID | 18 / 26 | Flags(1) · RESERVED(1) · SRv6-SID(16) · [SRv6 Endpoint Behavior & Structure(8)] |
| 14 | ENLP | 3 | Flags(1) · RESERVED(1) · ENLP(1) |
| 15 | Priority | 2 | Priority(1) · RESERVED(1) |
| 128 | Segment List | var | RESERVED(1) · nested sub-TLVs (Weight + Segments) |
| 129 | CP Name | var (≥1) | RESERVED(1) · CP Name (UTF-8, variable) |
| 130 | Policy Name | var (≥1) | RESERVED(1) · Policy Name (UTF-8, variable) |

Flag bits:
- **Binding SID (13)**: S = bit 0 (specified-BSID-only), I = bit 1 (drop-upon-invalid).
- **SRv6 Binding SID (20)**: S = bit 0, I = bit 1, B = bit 2 (Endpoint Behavior &
  Structure present → the optional 8 octets follow).
- **Preference (12)** Flags: D = bit 0 (draft) — store raw, no semantics in v1.

ENLP values: 1 = push IPv4 ExpNull only; 2 = push IPv6 ExpNull only;
3 = push both; 4 = do not push.

> ✅ Name sub-TLVs (129/130): the layout is Type(1) · Length(2) · RESERVED(1)
> · Name(UTF-8, var). There **is** a leading RESERVED octet before the name
> (RFC 9830 Figures 17 & 18, confirmed against the RFC text). An earlier draft
> of this doc claimed "no RESERVED octet" — that was **wrong**; the code
> (`srpolicy.rs`, PR #1063) skips the RESERVED octet on read and zeroes it on
> write, with a dedicated byte-offset test.

### Segment List (128) inner sub-TLVs

| Code | Name | Length | Fields (octets) |
|-----:|------|-------:|-----------------|
| 9 | Weight | 6 | Flags(1) · RESERVED(1) · Weight(4) |
| 1 | Segment Type A (SR-MPLS) | 6 | Flags(1) · RESERVED(1) · Label/TC/S/TTL(4) |
| 13 | Segment Type B (SRv6) | 18 / 26 | Flags(1) · RESERVED(1) · SRv6-SID(16) · [SRv6 Endpoint Behavior & Structure(8)] |

Type A label word (4 octets): `Label(20 bits) | TC(3 bits) | S(1 bit) | TTL(8 bits)`.
Decode `label = (word >> 12) & 0xFFFFF`.

Segment flags (Type A/B): **V = bit 0** (SID verification), **B = bit 3**
(SRv6 Endpoint Behavior & SID Structure present). Other bits unassigned.

**SRv6 Endpoint Behavior & SID Structure (optional, 8 octets):**
`Endpoint-Behavior(2) · RESERVED(2) · Locator-Block-Len(1) · Locator-Node-Len(1)
· Function-Len(1) · Argument-Len(1)`. Present iff B-flag set (and Length = 26).

### Full IANA segment registry (for the deferred follow-up)

`SR Policy Segment List Sub-TLVs`: 0 Reserved · 1 Type A · 3 Type C · 4 Type D
· 5 Type E · 6 Type F · 7 Type G · 8 Type H · 9 Weight · 13 Type B · 14 Type I
· 15 Type J · 16 Type K. Codes **2, 10, 11, 12 are not assigned in the current
registry** (deprecated draft codepoints) → decode as `Unknown`, preserve bytes.

## Proposed Rust design — `crates/bgp-packet/src/attrs/srpolicy.rs` (new)

Mirror the idiom of `nlri_srpolicy.rs` / `tunnel_encap.rs`: `bytes::{BufMut,
BytesMut}`, `nom::number::complete::{be_u8, be_u16, be_u32}`,
`nom::IResult`, derive `Debug, Clone, PartialEq, Eq, Hash`.

```rust
pub struct SrPolicyTlvs {
    pub preference: Option<u32>,
    pub binding_sid: Option<BindingSid>,
    pub srv6_binding_sid: Option<Srv6BindingSid>,
    pub enlp: Option<u8>,
    pub priority: Option<u8>,
    pub segment_lists: Vec<SegmentList>,
    pub policy_name: Option<String>,
    pub cp_name: Option<String>,
    pub unknown: Vec<TunnelSubTlv>,   // preserve unrecognised policy sub-TLVs
}

pub enum BindingSid { None, MplsLabel(u32), Srv6(Ipv6Addr) }   // sub-TLV 13 (len 2/6/18)

pub struct Srv6BindingSid {                                    // sub-TLV 20
    pub flags: u8,                                             // S,I,B
    pub sid: Ipv6Addr,
    pub structure: Option<Srv6SidStructure>,                  // present iff B-flag / len==26
}

pub struct SegmentList {                                       // sub-TLV 128
    pub weight: Option<u32>,                                   // inner code 9
    pub segments: Vec<Segment>,
}

pub enum Segment {
    TypeA { flags: u8, label: u32 },                          // code 1  (SR-MPLS)
    TypeB { flags: u8, sid: Ipv6Addr,                         // code 13 (SRv6)
            structure: Option<Srv6SidStructure> },
    Unknown { code: u8, value: Vec<u8> },                     // C–K + deprecated, preserved
}

pub struct Srv6SidStructure {                                 // 8 octets
    pub endpoint_behavior: u16,
    pub locator_block_len: u8,
    pub locator_node_len: u8,
    pub function_len: u8,
    pub argument_len: u8,
}
```

API surface:
- `impl SrPolicyTlvs { pub fn from_tunnel(t: &TunnelTlv) -> Result<Self, SrPolicyError>; pub fn to_tunnel(&self) -> TunnelTlv; }`
  (`to_tunnel` always emits `tunnel_type = 15`). This keeps the generic
  `TunnelEncap` as the carrier and makes the typed view a lossless-ish
  projection (unknowns preserved in `unknown` / `Segment::Unknown`).
- Convenience: `TunnelEncap::sr_policy(&self) -> Option<Result<SrPolicyTlvs, _>>`
  returning the first `tunnel_type == 15` TLV decoded. (Optional; can live in
  `srpolicy.rs` as a free fn to avoid touching `tunnel_encap.rs`.)

Validation (codec-level, keep minimal):
- Reject a Segment List that mixes SR-MPLS (Type A) and SRv6 (Type B).
- Reject Type B / SRv6 BSID whose Length is neither 18 nor 26.
- Reject Type A whose Length ≠ 6, Weight ≠ 6, Preference ≠ 6, Priority ≠ 2,
  ENLP ≠ 3.
- RESERVED ignored on read, zeroed on write. Unknown segment/policy sub-TLVs
  preserved verbatim (reflector-friendly).

## Integration points

1. `attrs/mod.rs` — add after the `nlri_srpolicy` block (line ~110):
   ```rust
   pub mod srpolicy;
   pub use srpolicy::*;
   ```
2. No change needed to `attr.rs` / `bgp_attr.rs`: type-23 already parses into
   `bgp_attr.tunnel_encap`. PR2 is purely additive codec surface. (The
   consumer that calls `SrPolicyTlvs::from_tunnel` is PR3's receive handler.)
3. Naming: file is `srpolicy.rs` (typed TLVs) — distinct from the existing
   `nlri_srpolicy.rs` (NLRI). Keep them separate.

## Test plan (the real verification — author explicit byte vectors)

In `srpolicy.rs` `#[cfg(test)]`, following `tunnel_encap.rs` style:
- Round-trip each policy sub-TLV (Preference, BSID MPLS, SRv6 BSID w/ and w/o
  structure, ENLP, Priority, Policy Name, CP Name).
- Segment List: Weight + Type A (MPLS label, check 20-bit extraction) +
  Type B (SRv6, w/ and w/o 8-octet structure).
- A full Tunnel-Type-15 TLV with Preference + BSID + two Segment Lists →
  `from_tunnel` → `to_tunnel` → byte-equal (modulo zeroed RESERVED).
- Negative: mixed SR-MPLS/SRv6 in one list rejected; bad lengths rejected;
  unknown segment code (e.g. 5 = Type C) preserved as `Segment::Unknown`.
- Cross-check exact byte offsets with hand-built `Vec<u8>` (don't only
  round-trip — assert on the wire bytes, as `short_sub_tlv_uses_one_byte_length`
  does).

## Open interop items (validate vs IOS-XR / pcap)

- **Type B codepoint:** current IANA = **13**. The original draft used **2**
  (now deprecated). If an IOS-XR capture shows code 2 for SRv6 segments,
  decode 2 as Type B too (alias). Default: 13 only, 2 → Unknown.
- **Name sub-TLV (129/130) RESERVED:** there **is** a leading RESERVED octet
  (RFC 9830 Fig 17/18) — implemented that way in `srpolicy.rs`. (An earlier
  draft wrongly said "no RESERVED octet".)
- **Binding SID (13) carrying a 16-octet SRv6 SID** (Length 18) is legal in
  addition to the dedicated SRv6 BSID (20); both handled by `BindingSid`.

## Verification checklist for the clean session

1. `cargo build -p bgp-packet`
2. `cargo test -p bgp-packet srpolicy` (new tests) + full `cargo test -p bgp-packet`
3. `cargo clippy --workspace --all-targets -- -D warnings`
4. `cargo fmt --all`
5. PR via `/merge-pr` flow; keep branch (PR3 follows). CI is source of truth.
