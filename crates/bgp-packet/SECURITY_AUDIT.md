# bgp-packet Security Audit

**Original audit date:** 2026-04-09
**Re-verified:** 2026-06-26 against the current workspace tree
**Crate version:** 26.6.2 (workspace versioning)
**nom version:** 7.1.3
**Scope:** current workspace tree under `crates/bgp-packet/`

## Summary

This revision re-verifies the four findings from the previous audit against the
current source. Two of them — both the High-severity panic paths — are now
fully fixed and covered by regression tests. The two Medium-severity findings
are partly addressed: the MP_REACH `nhop_len` case is fixed, but the
trailing-garbage class and the EVPN substructure-length cases remain open. The
residual encoder-side `u8` truncation issues are unchanged.

Status of the four previously reported issues:

1. **High — FIXED:** UPDATE attribute-block parsing now bounds the slice with
   `packet_utils::safe_split_at()` instead of a raw `split_at()`.
2. **High — FIXED:** IPv4 and IPv6 NLRI parsers now reject overlong prefix
   lengths before computing the prefix byte size.
3. **Medium — OPEN:** several length-bounded BGP subparsers still ignore inner
   remainders and silently discard trailing garbage.
4. **Medium — PARTIALLY FIXED:** MP_REACH now validates `nhop_len`; EVPN
   per-route `length` and multicast `addr_len` are still not enforced.

The residual encoder-side `u8` truncation issues for oversized capabilities are
unchanged. They are local packet-construction problems rather than
network-triggered parser bugs.

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

### 3. Length-bounded payloads still accept trailing garbage — OPEN

- **Severity:** Medium
- **Files:**
  - `src/attrs/cluster_list.rs`
  - `src/caps/packet.rs`
  - `src/attrs/nlri_ipv4.rs`

The outer parsers now bound their slice with `safe_split_at()`, but they still
ignore the inner parser's remainder rather than rejecting a non-empty one:

- `ClusterList::parse_be()` (`cluster_list.rs:24`) uses
  `many0_complete(be_u32)`, so a 5-byte payload is accepted as one cluster ID
  plus one discarded byte.
- `CapabilityPacket::parse_cap()` (`caps/packet.rs:66`) discards the inner
  remainder: `let (_, cap) = CapabilityPacket::parse_be(cap, …)?;`.
- `parse_bgp_nlri_ipv4()` (`nlri_ipv4.rs:45`) uses `many0_complete(...)` and
  drops any trailing bytes after the last valid NLRI.

- **Impact:** Malformed wire data is normalized into a different in-memory
  object and the dropped bytes vanish on re-emit, creating parser-differential
  and canonicalization problems.
- **Recommendation:** After parsing each bounded slice, reject any non-empty
  remainder instead of discarding it.

### 4. Substructure length fields not enforced — PARTIALLY FIXED

- **Severity:** Medium
- **Files:**
  - `src/attrs/mp_reach.rs` (fixed)
  - `src/attrs/nlri_evpn.rs` (open)

**Fixed — MP_REACH `nhop_len`.** `parse_nlri_opt()` now matches on
`header.nhop_len` for every AFI/SAFI and rejects unexpected lengths instead of
assuming a fixed nexthop width. VPNv4 accepts only 12/24/48 (`mp_reach.rs:200`),
VPNv6 only 24/48 (`mp_reach.rs:254`), and any other value returns
`Err(ErrorKind::LengthValue)`.

**Open — EVPN per-route `length`.** `EvpnRoute::parse_nlri()`
(`nlri_evpn.rs:752`) reads the per-route `length` octet but only uses it for the
`IpPrefix` family-width selection (`nlri_evpn.rs:853`). The other route types
(EthernetAd, EthernetSr, MacIpAdvRoute, IncMulticast) decode their fields
without splitting the payload to `length` first. There is no
`safe_split_at()`/`split_at()` anywhere in the file.

**Open — EVPN multicast `addr_len`.** `nlri_evpn.rs:828` treats any `addr_len`
other than `32` as a 16-byte IPv6 address (`else { take(16) }`) without
validating that the value is `128`.

- **Recommendation:** Bound each EVPN route body to its declared `length`,
  parse within that slice, reject a non-empty remainder, and validate
  `addr_len` against the expected `32`/`128` before decoding.

## Residual Hardening Issues — unchanged

These remain lower severity because they affect local packet construction
rather than parsing untrusted network data. All still present:

- capability encoders compute wire lengths with unchecked `as u8` casts:
  - `CapAddPath::len()` (`caps/addpath.rs:101`)
  - `CapRestart::len()` (`caps/graceful.rs:59`)
  - `CapLlgr::len()` (`caps/llgr.rs:68`)
  - `CapPathLimit::len()` (`caps/path_limit.rs:39`)
  - `CapFqdn::len()` (`caps/fqdn.rs:48`)
  - `CapVersion::len()` (`caps/version.rs:35`)
  - `CapUnknown::len()` (`caps/unknown.rs:29`)
- `CapFqdn::emit_value()` (`caps/fqdn.rs:52,54`) casts `hostname.len()` and
  `domain.len()` to `u8` independently, so oversized values can produce
  internally inconsistent encodings.

Recommended follow-up:

1. replace `as u8` conversions on wire lengths with `u8::try_from(...)` where
   oversize data should be rejected.
2. compute aggregate lengths in `usize`, then convert once at the wire
   boundary.
3. add regression tests for oversized local constructors.

## Recommended Priority

### Priority 1 — DONE

1. ~~Replace the raw `split_at()` in `parse_bgp_update_attribute()`.~~ Fixed.
2. ~~Add explicit IPv4/IPv6 prefix-length validation before `nlri_psize()`.~~
   Fixed.

### Priority 2 — partially open

3. Enforce full consumption for all length-bounded attribute, capability, and
   NLRI slices (Finding 3).
4. Enforce the EVPN per-route `length` and multicast `addr_len` (the remaining
   half of Finding 4). MP_REACH `nhop_len` is done.

### Priority 3 — open

5. Convert remaining encoder-side `u8` length arithmetic to checked arithmetic.
6. Add malformed-length regression tests for the still-open cases:
   - attribute/capability/NLRI payloads with valid prefixes plus trailing
     garbage
   - EVPN substructures with inconsistent embedded lengths and non-`32`/`128`
     `addr_len`

## Verification

The current tree was validated with:

```sh
cargo test -p bgp-packet
```
