# bgp-packet Security Audit

**Audit date:** 2026-04-09  
**Crate version:** 0.9.0  
**nom version:** 8.0.0  
**Scope:** current workspace tree under `crates/bgp-packet/`

## Summary

This revision supersedes the earlier audit document in this crate.

Several previously reported problems are fixed in the current tree:

- the old unchecked `split_at()` calls in OPEN optional-parameter parsing,
  capability parsing, and IPv4 NLRI block parsing have been replaced with
  `packet_utils::safe_split_at()`.
- the UPDATE and NOTIFICATION length-underflow paths now use
  `saturating_sub()`.
- attribute flags now use `AttributeFlags::from_bits_truncate()`.
- the 2-octet aggregator conversion now correctly clamps at `u16::MAX`.
- VPNv4 NLRI now validates `plen >= 88` before parsing the label and route
  distinguisher.
- `peek_bgp_length()` no longer uses `unwrap()`.

I still found four current security-relevant issues:

1. **High:** UPDATE attribute-block parsing still contains a reachable raw
   `split_at()` panic.
2. **High:** IPv4 and IPv6 NLRI parsers still panic on overlong prefix lengths.
3. **Medium:** several length-bounded BGP subparsers ignore inner remainders
   and silently discard trailing garbage.
4. **Medium:** some protocol length fields are parsed but not enforced,
   especially in MP_REACH and EVPN NLRI substructures.

There are also residual encoder-side `u8` truncation issues for oversized
capabilities, but those are local packet-construction problems rather than
network-triggered parser bugs.

## Current Findings

### 1. UPDATE attribute-block parsing still panics on oversized `attr_len`

- **Severity:** High
- **Files:**
  - `src/attrs/attr.rs`
  - `src/update.rs`

Relevant code:

```rust
pub fn parse_bgp_update_attribute(
    input: &[u8],
    length: u16,
    as4: bool,
    opt: Option<ParseOption>,
) -> ParsedAttributes<'_> {
    let (attr, input) = input.split_at(length as usize);
    // ...
}
```

- **Problem:** `length` comes directly from the untrusted UPDATE `attr_len`
  field. Unlike the earlier fixed call sites, this path still uses raw
  `split_at()` without checking that `input.len() >= length as usize`.
- **Trigger:** A malformed UPDATE message with an attribute length larger than
  the remaining bytes after the withdrawn-routes field.
- **Impact:** Immediate panic and daemon crash from crafted wire input.
- **Recommendation:** Replace this with `packet_utils::safe_split_at()` or an
  explicit length check that returns a parse error instead of panicking.

### 2. IPv4 and IPv6 NLRI parsers still panic on overlong prefix lengths

- **Severity:** High
- **Files:**
  - `src/attrs/nlri_ipv4.rs`
  - `src/attrs/nlri_ipv6.rs`

Representative snippets:

```rust
let (input, plen) = be_u8(input)?;
let psize = nlri_psize(plen);
let mut paddr = [0u8; 4];
paddr[..psize].copy_from_slice(&input[..psize]);
```

```rust
let (input, plen) = be_u8(input)?;
let psize = nlri_psize(plen);
let mut paddr = [0u8; 16];
paddr[..psize].copy_from_slice(&input[..psize]);
```

- **Problem:** `nlri_psize()` is computed before validating the address-family
  prefix bound. For IPv4, `plen = 33` produces `psize = 5`; for IPv6,
  `plen = 129` produces `psize = 17`. Both then index beyond the fixed address
  buffer.
- **Reachability:** This affects multiple paths:
  - classic IPv4 UPDATE NLRI
  - classic IPv4 withdrawn routes
  - MP_REACH IPv6 unicast NLRI
  - MP_UNREACH IPv6 unicast NLRI
  - any caller using the `ParseBe<Ipv6Net>` helper
- **Impact:** Immediate panic and daemon crash from malformed BGP input.
- **Recommendation:** Reject `plen > 32` for IPv4 and `plen > 128` for IPv6
  before computing `psize` or slicing the fixed buffer.

### 3. Length-bounded attribute, capability, and NLRI payloads accept trailing garbage

- **Severity:** Medium
- **Files:**
  - `src/attrs/attr.rs`
  - `src/open.rs`
  - `src/caps/packet.rs`
  - `src/attrs/nlri_ipv4.rs`
  - `src/attrs/cluster_list.rs`

Representative patterns:

```rust
let (_, attr) = Attr::parse_be(attr_payload, AttrSelector(attr_type, as4_opt))?;
```

```rust
let (_, caps) = many0_complete(CapabilityPacket::parse_cap).parse(opts)?;
```

```rust
let (_, nlris) = many0_complete(|i| Ipv4Nlri::parse_nlri(i, add_path)).parse(nlri)?;
```

- **Problem:** The outer parser correctly bounds a slice using a wire-format
  length field, but then ignores the inner parser's remainder. If the inner
  parser consumes only a prefix of that bounded slice, the trailing bytes are
  silently discarded.
- **Concrete examples:**
  - `ClusterList::parse_be()` uses `many0_complete(be_u32)`, so a 5-byte
    payload is accepted as one cluster ID plus one discarded byte.
  - `CapabilityPacket::parse_cap()` ignores any bytes left over after a
    capability-specific parser such as FQDN parsing.
  - `parse_bgp_nlri_ipv4()` can accept an NLRI block containing one valid NLRI
    followed by trailing junk.
- **Impact:** Malformed wire data is normalized into a different in-memory
  object and the dropped bytes vanish on re-emit. That creates parser
  differential and canonicalization problems.
- **Recommendation:** Require full consumption of every bounded slice. After
  parsing, reject any non-empty remainder instead of discarding it.

### 4. Some BGP substructure length fields are read but not enforced

- **Severity:** Medium
- **Files:**
  - `src/attrs/mp_reach.rs`
  - `src/attrs/nlri_evpn.rs`

Representative examples:

```rust
if header.afi == Afi::Ip && header.safi == Safi::MplsVpn {
    let (input, rd) = RouteDistinguisher::parse_be(input)?;
    let (input, nhop) = be_u32(input)?;
    // header.nhop_len is never checked here
}
```

```rust
let (input, _length) = be_u8(input)?;
// route-specific parsing ignores the declared EVPN route length
```

- **Problem:** Certain protocol length fields are parsed but not actually used
  to bound the following substructure.
- **Concrete cases:**
  - VPNv4 MP_REACH ignores `nhop_len` and always parses a fixed 12-byte nexthop
    (RD + IPv4 address).
  - EVPN route parsing reads the per-route `length` octet but does not split
    the route payload to that length before decoding route-specific fields.
  - EVPN multicast treats any `addr_len` other than `32` as a 16-byte IPv6
    address instead of validating the value.
- **Impact:** A malformed substructure can consume bytes outside its declared
  boundary and shift the parse of subsequent data. This is not a direct panic
  path in the current tree, but it is a correctness and interoperability risk.
- **Recommendation:** Use each declared substructure length to create a bounded
  slice, parse within that slice, and reject non-empty remainders.

## Residual Hardening Issues

These are lower severity because they affect local packet construction rather
than parsing untrusted network data:

- multiple capability encoders still compute wire lengths with unchecked `u8`
  casts, including:
  - `CapAddPath::len()`
  - `CapRestart::len()`
  - `CapLlgr::len()`
  - `CapPathLimit::len()`
  - `CapFqdn::len()`
  - `CapVersion::len()`
  - `CapUnknown::len()`
- `CapFqdn::emit_value()` also casts `hostname.len()` and `domain.len()` to
  `u8` independently, so oversized values can produce internally inconsistent
  encodings.

Recommended follow-up:

1. replace `as u8` conversions on wire lengths with `u8::try_from(...)` where
   oversize data should be rejected.
2. compute aggregate lengths in `usize`, then convert once at the wire
   boundary.
3. add regression tests for oversized local constructors.

## Recommended Priority

### Priority 1

1. Replace the raw `split_at()` in `parse_bgp_update_attribute()`.
2. Add explicit IPv4/IPv6 prefix-length validation before `nlri_psize()`.

### Priority 2

3. Enforce full consumption for all length-bounded attribute, capability, and
   NLRI slices.
4. Enforce `nhop_len`, EVPN route length, and other parsed substructure length
   fields.

### Priority 3

5. Convert remaining encoder-side `u8` length arithmetic to checked arithmetic.
6. Add malformed-length regression tests for:
   - oversized UPDATE `attr_len`
   - IPv4 `plen > 32`
   - IPv6 `plen > 128`
   - attribute/capability payloads with valid prefixes plus trailing garbage
   - MP_REACH / EVPN substructures with inconsistent embedded lengths

## Verification

The current tree was validated with:

```sh
cargo test -p bgp-packet
```

All tests passed at the time of this revision.
