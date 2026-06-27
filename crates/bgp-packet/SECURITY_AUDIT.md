# bgp-packet Security Audit

**Original audit date:** 2026-04-09
**Re-verified:** 2026-06-26 against the current workspace tree
**Crate version:** 26.6.2 (workspace versioning)
**nom version:** 7.1.3
**Scope:** current workspace tree under `crates/bgp-packet/`

## Summary

This revision re-verifies the four findings from the previous audit against the
current source. All four are now fully fixed and covered by regression tests:
both High-severity panic paths, the Medium-severity trailing-garbage class, and
the Medium-severity substructure-length cases (MP_REACH `nhop_len`, EVPN
per-route `length`, and EVPN multicast `addr_len`). The only remaining items
are the residual encoder-side `u8` truncation issues; `CapFqdn` and `CapVersion`
are now fixed, and the other capability encoders are still open.

Status of the four previously reported issues:

1. **High — FIXED:** UPDATE attribute-block parsing now bounds the slice with
   `packet_utils::safe_split_at()` instead of a raw `split_at()`.
2. **High — FIXED:** IPv4 and IPv6 NLRI parsers now reject overlong prefix
   lengths before computing the prefix byte size.
3. **Medium — FIXED:** the length-bounded BGP subparsers now enforce full
   consumption of their bounded slice and reject trailing garbage.
4. **Medium — FIXED:** MP_REACH validates `nhop_len`, and the EVPN parser now
   bounds each route body to its declared `length` and validates the multicast
   `addr_len`.

The residual encoder-side `u8` truncation issues for oversized capabilities are
local packet-construction problems rather than network-triggered parser bugs.
`CapFqdn` and `CapVersion` are now fixed (clamped wire lengths derived from a
single helper each); the other capability encoders remain.

Earlier hardening that remains in place (carried over from the prior revision):
the OPEN optional-parameter, capability, and IPv4 NLRI block parsers use
`packet_utils::safe_split_at()`; UPDATE/NOTIFICATION length-underflow paths use
`saturating_sub()`; attribute flags use `AttributeFlags::from_bits_truncate()`;
the 2-octet aggregator conversion clamps at `u16::MAX`; VPNv4 NLRI validates
`plen >= 88`; and `peek_bgp_length()` no longer uses `unwrap()`.

## Findings

### 1. UPDATE attribute-block parsing — FIXED

- **Severity:** High
- **Files:**
  - `src/attrs/attr.rs`
  - `src/update.rs`

`parse_bgp_update_attribute()` (`src/attrs/attr.rs:345`) now bounds the
attribute block with `packet_utils::safe_split_at()` before iterating:

```rust
let length = length as usize;
let (input, attr) = packet_utils::safe_split_at(input, length).map_err(BgpParseError::from)?;
```

An oversized `attr_len` returns a parse error instead of panicking. A regression
test, `parse_bgp_update_attribute_rejects_oversized_length` (`attr.rs:517`),
pins this behavior. The sibling call site at `attr.rs:263` also uses
`safe_split_at()`.

### 2. IPv4 and IPv6 NLRI overlong prefix lengths — FIXED

- **Severity:** High
- **Files:**
  - `src/attrs/nlri_ipv4.rs`
  - `src/attrs/nlri_ipv6.rs`

Both parsers now validate the address-family prefix bound before computing
`nlri_psize()`, and additionally check that the buffer holds `psize` bytes:

```rust
let (input, plen) = be_u8(input)?;
if plen > 32 {                       // 128 for IPv6
    return Err(nom::Err::Error(make_error(input, ErrorKind::Verify)));
}
let psize = nlri_psize(plen);
if input.len() < psize {
    return Err(nom::Err::Error(make_error(input, ErrorKind::Eof)));
}
```

This covers all reachable paths the prior audit listed, including the
`ParseBe<Ipv6Net>` helper (`nlri_ipv6.rs:61`), which carries the same guard.
Regression tests: `parse_nlri_rejects_prefixlen_over_32` (IPv4),
`parse_nlri_rejects_prefixlen_over_128` and
`parse_ipv6net_rejects_prefixlen_over_128` (IPv6).

### 3. Length-bounded payloads accepted trailing garbage — FIXED

- **Severity:** Medium
- **Files:**
  - `src/attrs/cluster_list.rs`
  - `src/attrs/nlri_ipv4.rs`
  - `src/caps/packet.rs`
  - `src/open.rs`

The outer parsers bounded their slice with `safe_split_at()` but then ignored
the inner parser's remainder, so a non-empty leftover was silently discarded.
Each bounded slice now enforces full consumption:

- `ClusterList::parse_be()` (`cluster_list.rs:25`) rejects a payload whose
  length is not a multiple of 4 up front
  (`if !input.len().is_multiple_of(4)`), so a stray trailing octet can no longer
  be swallowed by `many0_complete(be_u32)`.
- `parse_bgp_nlri_ipv4()` (`nlri_ipv4.rs:38`) drains the bounded slice in an
  explicit loop (`while !nlri.is_empty()`), so a malformed or truncated trailing
  NLRI surfaces the real parse error from `Ipv4Nlri::parse_nlri()` instead of
  being dropped by `many0_complete()`.
- `CapabilityPacket::parse_cap()` (`caps/packet.rs:63`) now binds the inner
  remainder and returns `Err(ErrorKind::LengthValue)` when it is non-empty,
  rather than discarding it with `let (_, cap) = …`.
- `OpenPacket::parse_packet()` and the `parse_caps()` helper (`open.rs:65,79`)
  apply the same non-empty-remainder rejection to the OPEN optional-parameter
  and capability-block slices.

- **Impact (historical):** Malformed wire data was normalized into a different
  in-memory object and the dropped bytes vanished on re-emit, creating
  parser-differential and canonicalization problems.
- **Regression tests:** `parse_cluster_list_rejects_non_multiple_of_four`
  (`cluster_list.rs`), `parse_bgp_nlri_ipv4_rejects_trailing_garbage` and
  `parse_bgp_nlri_ipv4_consumes_whole_block` (`nlri_ipv4.rs`).

### 4. Substructure length fields not enforced — FIXED

- **Severity:** Medium
- **Files:**
  - `src/attrs/mp_reach.rs`
  - `src/attrs/nlri_evpn.rs`

**Fixed — MP_REACH `nhop_len`.** `parse_nlri_opt()` now matches on
`header.nhop_len` for every AFI/SAFI and rejects unexpected lengths instead of
assuming a fixed nexthop width. VPNv4 accepts only 12/24/48 (`mp_reach.rs:200`),
VPNv6 only 24/48 (`mp_reach.rs:254`), and any other value returns
`Err(ErrorKind::LengthValue)`.

**Fixed — EVPN per-route `length`.** `EvpnRoute::parse_nlri()`
(`nlri_evpn.rs:748`) now bounds the route body to its declared `length` octet
with `packet_utils::safe_split_at()` (`nlri_evpn.rs:758`) before dispatching on
the route type, so no field can read past the NLRI into the next one. After the
per-type parse it rejects any non-empty remainder inside the bounded body
(`nlri_evpn.rs:1057`) with `Err(ErrorKind::LengthValue)`, so a field shorter
than the declared length — or a padded length — fails the parse instead of
silently dropping the extra octets.

**Fixed — EVPN multicast `addr_len`.** The Inclusive Multicast (Type-3) arm
now matches `addr_len` against `32` (IPv4) and `128` (IPv6) explicitly
(`nlri_evpn.rs:834`); any other value returns `Err(ErrorKind::LengthValue)`
rather than being read as a 16-octet IPv6 address.

Regression tests: `inclusive_multicast_rejects_bad_addr_len` and
`parse_nlri_rejects_trailing_body_bytes` (`nlri_evpn.rs`).

## Residual Hardening Issues — CapFqdn & CapVersion fixed, others open

These are lower severity because they affect local packet construction rather
than parsing untrusted network data.

**Fixed — `CapFqdn`.** `CapFqdn::len()` and `emit_value()` now derive both the
declared length and the emitted bytes from a single `wire_lengths()` helper
(`caps/fqdn.rs`). The hostname and domain share a 251-octet budget (the
capability value is at most 253 octets — the optional-parameter length octet is
`len() + 2` — minus the two name-length octets); the hostname is given priority
and the domain takes the remainder. Both length octets are always emitted, the
clamped counts are `<= 251` so the `as u8` casts can no longer truncate, and the
length octets always match the bytes written. Regression tests cover the normal,
both-empty, oversized-hostname, oversized-domain, and hostname-priority cases.

**Fixed — `CapVersion`.** The version string is the whole capability value (no
internal length octet), so `len()` and `emit_value()` now derive from a single
`wire_len()` helper (`caps/version.rs`) that clamps the version to the 253-octet
capability-value budget. The `as u8` length cast can no longer truncate, the
length octet always matches the bytes written, and `len() + 2` stays within a
u8. Regression tests cover the normal, empty, and oversized cases.

**Still present — the other capability encoders** compute wire lengths with
unchecked `as u8` casts:

- `CapAddPath::len()` (`caps/addpath.rs:101`)
- `CapRestart::len()` (`caps/graceful.rs:59`)
- `CapLlgr::len()` (`caps/llgr.rs:68`)
- `CapPathLimit::len()` (`caps/path_limit.rs:39`)
- `CapUnknown::len()` (`caps/unknown.rs:29`)

A related latent issue affects all capabilities: the shared `CapEmit::emit()`
(`caps/emit.rs:23`) writes the optional-parameter length as
`put_u8(self.len() + 2)`, which overflows a `u8` if any capability's `len()`
reaches 254–255. The `CapFqdn` and `CapVersion` fixes bound their values at 253
so they never trigger this; the remaining encoders should adopt the same bound
(or `emit()` should saturate / reject).

Recommended follow-up:

1. clamp or `u8::try_from(...)` the remaining capability wire-length casts the
   same way (compute aggregate lengths in `usize`, convert once at the wire
   boundary), and bound or saturate the shared `emit()` optional-parameter
   length.
2. add regression tests for oversized local constructors.

## Recommended Priority

### Priority 1 — DONE

1. ~~Replace the raw `split_at()` in `parse_bgp_update_attribute()`.~~ Fixed.
2. ~~Add explicit IPv4/IPv6 prefix-length validation before `nlri_psize()`.~~
   Fixed.

### Priority 2 — DONE

3. ~~Enforce full consumption for all length-bounded attribute, capability, and
   NLRI slices (Finding 3).~~ Fixed.
4. ~~Enforce the EVPN per-route `length` and multicast `addr_len` (the remaining
   half of Finding 4).~~ Fixed. MP_REACH `nhop_len` was already done.

### Priority 3 — partially open

5. Convert the remaining encoder-side `u8` length arithmetic to clamped/checked
   arithmetic (`CapAddPath`, `CapRestart`, `CapLlgr`, `CapPathLimit`,
   `CapUnknown`), and bound or saturate the shared `CapEmit::emit()`
   optional-parameter length (`emit.rs:23`). `CapFqdn` and `CapVersion` are
   done.

## Verification

The current tree was validated with:

```sh
cargo test -p bgp-packet
```
