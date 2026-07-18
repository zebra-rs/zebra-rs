# bgp-packet Security Audit

**Original audit:** 2026-04-09 · **Re-audits:** 2026-06-26, 2026-06-27 (full
parse + emit sweep), 2026-07-17 (independent re-verification + fresh sweep)
**Scope:** `crates/bgp-packet/` · nom 7.1.3

## Status: no open findings

Every finding from every audit pass is fixed and pinned by a regression test.
The 2026-07-17 pass independently re-verified all prior fixes against the tree,
found no panic / DoS / memory-safety issue, and closed the last two
trailing-garbage gaps (ExtCommunities, MUP — see below). Verify with
`cargo test -p bgp-packet`.

## Fixed findings (condensed history)

**High — UPDATE attribute-block bounds.** `parse_bgp_update_attribute()` and
the per-attribute framing in `parse_attr_header` bound their slices with
`packet_utils::safe_split_at()` (`attrs/attr.rs:370`, `:271`); no raw
`split_at()` on untrusted input anywhere in the crate. Test:
`parse_bgp_update_attribute_rejects_oversized_length`.

**High — NLRI prefix-length validation.** IPv4/IPv6 NLRI (and the
`ParseBe<Ipv6Net>` helper) reject `plen > 32/128` before `nlri_psize()` and
check the buffer holds `psize` bytes. Same pattern in vpnv4/vpnv6
(`plen >= 88`), labeled-unicast (`plen >= 24`), MUP ISD/T1ST. Tests:
`parse_nlri_rejects_prefixlen_over_{32,128}`,
`parse_ipv6net_rejects_prefixlen_over_128`.

**Medium — length-bounded payloads must be fully consumed (RFC 7606 class).**
A bounded slice whose inner parse leaves a remainder is rejected
(`ErrorKind::LengthValue`), never silently dropped:

- `Community` (non-zero multiple of 4), `LargeCommunity` (×12), `ClusterList`
  (×4), and — since 2026-07-17 — `ExtCommunity` (non-zero multiple of 8, RFC
  7606 §7.14, `attrs/ext_com.rs`).
- `parse_bgp_nlri_ipv4()` drains its block in an explicit loop; OPEN
  optional-parameter / capability blocks and `CapabilityPacket::parse_cap()`
  reject non-empty remainders (`open.rs`, `caps/packet.rs`).
- EVPN: per-route body bounded to its declared `length` octet and any
  remainder rejected (`nlri_evpn.rs:770,1084`); Type-3 `addr_len` must be
  32/128. Since 2026-07-17 MUP enforces the same rule: every route-type arm
  (ISD/DSD/T1ST/T2ST) rejects leftover bytes inside its `take(length)` body
  (`nlri_mup.rs`). Tests: `*_rejects_padded_length` (MUP ×4),
  `parse_nlri_rejects_trailing_body_bytes`,
  `inclusive_multicast_rejects_bad_addr_len`,
  `parse_be_rejects_partial_trailing_value` (extcomm).

**Medium — MP_REACH `nhop_len`.** VPNv4 accepts only 12/24/48, VPNv6 only
24/48; EVPN/RTC/Link-State require 4 or 16 (`mp_reach.rs`). Note: the Flowspec
arm intentionally `take()`s whatever `nhop_len` says — length-safe (bounded by
the buffer), just not value-restricted.

**Low — encoder-side `u8` clamps.** All seven capability encoders derive
`len()` and `emit_value()` from one shared clamp helper so the `as u8` length
casts cannot truncate: `CapFqdn` (251-octet hostname+domain budget, hostname
priority), `CapVersion`/`CapUnknown` (253), `CapAddPath` (63×4),
`CapRestart` (62×4 + 2-octet header), `CapLlgr` (36×7), `CapPathLimit` (50×5).
`CapEmit::emit()` writes the optional-parameter length as
`len().saturating_add(2)` (`caps/emit.rs:29`). MUP T2ST emit clamps the TEID
width to 4 via `t2st_teid_size()` (former slice panic on a locally-built
route with out-of-range `endpoint_len`).

## Reviewed and intentionally left as-is

`payload.len() as u8` sites where a clamp would desync length from body:

- **Fixed-size EVPN bodies** (11 emitters in `nlri_evpn.rs`): worst case
  ≈79 octets (IgmpLeaveSync with IPv6 addresses) — far below 256, cast can't
  truncate.
- **Variable opaque bodies** (EVPN LeafAd `route_key`, MUP `Unknown` body,
  `tunnel_encap`/`srpolicy` TLV values with type < 128): bounded ≤255 on the
  parse path by the enclosing 1-octet length, so parse-then-re-emit never
  truncates; an oversized locally-built object is simply unencodable.
- **AS_PATH segment count** (`aspath.rs:177`): segments split at 255 via
  `chunks(AS_SEGMENT_MAX)`.

All other production `len as u8` sites sit behind an extended-length / u16
fallback (attribute emitter, vpnv4/v6, flowspec <240 rule, mp_reach/unreach,
RFC 9072 OPEN extension).

## 2026-07-17 re-verification notes

Three independent passes (findings re-check, encoder re-check, fresh
adversarial sweep of every parse module) confirmed:

- All prior fixes present; only prose drift in older revisions of this
  document (attr.rs line numbers, CapRestart wrongly described as "42×6",
  EVPN fixed-body bound understated as "≲60") — corrected above.
- Parse side clean: every slice index / length subtraction guarded
  (`saturating_sub` or explicit bound), all TLV loops make ≥1-byte progress
  (no infinite loops), no attacker-sized allocations, no
  `unwrap`/`expect`/`unreachable!` reachable from wire bytes (remaining ones
  are post-validation infallible or config-text `FromStr` paths).
- Two new low-severity trailing-garbage gaps found and fixed the same day
  (ExtCommunity ×8 guard, MUP padded per-route length — folded into the
  Medium finding above).
- IPv6 Address-Specific ExtCommunity (type 25, `ext_ipv6_com.rs`) is
  deliberately not wired into the `Attr` parser and is unreachable from the
  wire.

## Invariants to preserve (checklist for new parsers/emitters)

1. Bound every length-prefixed slice with `packet_utils::safe_split_at()`;
   never raw `split_at()` / direct indexing on wire input.
2. After parsing inside a bounded slice, reject a non-empty remainder
   (`ErrorKind::LengthValue`) — treat-as-withdraw semantics, no silent drops.
3. Validate prefix/address length octets against their family maximum before
   `nlri_psize()`; check buffer length before every fixed-width copy.
4. Fixed-width repeating attributes: reject payloads that are empty or not a
   multiple of the element size.
5. Emitters: derive `len()` and the emitted bytes from one shared
   clamp/count helper; a 1-octet length field needs either a proof the body
   can't reach 256 or a clamp that keeps length and body in sync.
