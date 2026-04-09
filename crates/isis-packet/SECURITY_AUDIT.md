# isis-packet Security Audit

**Audit date:** 2026-04-09  
**Crate version:** 0.9.0  
**nom version:** 8.0.0  
**Scope:** current workspace tree under `crates/isis-packet/`

## Summary

This revision supersedes the earlier 2026-03-19 audit.

The previously reported crash bugs around checksum indexing, unchecked
`split_at()`, and overlong IPv4/IPv6 prefix lengths are fixed in the current
tree. I did not find a current packet-triggered panic in this pass.

The remaining security-relevant issues are:

1. **High:** PDU wire-length fields are parsed but not enforced.
2. **Medium:** TLV/sub-TLV parsers accept trailing garbage inside
   length-bounded payloads and silently discard it.
3. **Medium:** `emit_sub_tlvs()` clamps the nested length field to 255 without
   truncating the emitted payload.

There are also a few lower-priority unchecked `u8` length calculations that can
still produce malformed packets when the library is used to construct oversized
TLVs programmatically.

## Status Since Prior Audit

The following items from the earlier report are now addressed:

- `is_valid_checksum()` validates short input before indexing.
- `IsisPacket::emit()` guards the LSP checksum write with `buf.len() >= 26`.
- `checksum_calc()` returns `[0, 0]` for too-short input.
- direct `split_at()` use in parsing paths was replaced with
  `packet_utils::safe_split_at()`.
- `ptake()` now rejects IPv4 prefix lengths greater than 32.
- `ptakev6()` now rejects IPv6 prefix lengths greater than 128.
- SRv6 sub2 parsing now respects the wire-format `sub2_len` field.
- unknown TLV parsing preserves payload bytes.
- `IsisTlvLspEntries::len()` uses the 16-byte wire size.
- `IsisTlvHostname::parse_be()` now consumes its full input.
- `SidLabelValue::parse_be()` now returns `Err::Error` for malformed lengths.
- the old unchecked sub2 back-patch sites were consolidated into
  `emit_sub_tlvs()`.

## Current Findings

### 1. PDU wire-length fields are not enforced

- **Severity:** High
- **Files:**
  - `src/parser.rs`
- **Relevant code:**
  - `IsisPacket` parses `length_indicator` and then directly dispatches to
    `IsisPdu::parse_be`.
  - the concrete PDU structs (`IsisLsp`, `IsisHello`, `IsisP2pHello`,
    `IsisCsnp`, `IsisPsnp`) parse TLVs with `IsisTlv::parse_tlvs`.
  - `IsisTlv::parse_tlvs()` continues until end-of-input.

Representative snippets:

```rust
pub struct IsisPacket {
    pub length_indicator: u8,
    #[nom(Parse = "{ |x| IsisPdu::parse_be(x, pdu_type) }")]
    pub pdu: IsisPdu,
}

pub struct IsisLsp {
    pub pdu_len: u16,
    #[nom(Parse = "IsisTlv::parse_tlvs")]
    pub tlvs: Vec<IsisTlv>,
}
```

- **Problem:** The parser reads `length_indicator` and the per-PDU `pdu_len`
  fields, but it never uses them to bound parsing. Once the fixed fields are
  read, TLVs are parsed to the end of the caller-provided slice.
- **Impact:** A crafted packet can advertise a shorter wire length while still
  appending extra TLVs. This crate accepts those bytes as part of the PDU,
  while a stricter implementation may stop at the declared boundary. That
  parser differential matters for any caller that treats `parse()` as a
  complete structural validation step.
- **Recommendation:** Split the PDU body using the declared wire length before
  calling `IsisTlv::parse_tlvs()`, and reject any non-empty remainder inside
  that bounded slice.

### 2. Length-bounded TLV and sub-TLV parsers discard trailing bytes

- **Severity:** Medium
- **Files:**
  - `src/parser.rs`
  - `src/sub/cap.rs`
  - `src/sub/neigh.rs`
  - `src/sub/prefix.rs`

Representative snippets:

```rust
let (input, tlv) = packet_utils::safe_split_at(input, tl.len as usize)?;
let (_, val) = Self::parse_be(tlv, tl.typ)?;

let (input, sub) = safe_split_at(input, cl.len as usize)?;
let (_, mut val) = Self::parse_be(sub, cl.code.into())?;
```

- **Problem:** The outer parser correctly slices out the declared TLV/sub-TLV
  payload, but it ignores the inner parser's remainder. As a result, malformed
  payloads with valid leading data and trailing garbage are accepted.
- **Examples:**
  - `IsisSubAdminGrp::parse_be()` reads `u32` values with
    `many0_complete(be_u32)`, so a 5-byte payload is accepted as one group plus
    one silently dropped byte.
  - `IsisTlvMultiTopology::parse_be()` accepts odd-length payloads and drops the
    final byte.
  - `IsisTlvP2p3Way::parse_be()` accepts 1-3 trailing bytes after the optional
    fields.
- **Impact:** Malformed packets normalize into a different in-memory object than
  the original wire payload. On re-emit, the discarded bytes disappear. This is
  a classic parser-canonicalization issue and can hide malformed data from later
  validation layers.
- **Recommendation:** Require full consumption of every length-bounded slice.
  Replace `let (_, val) = ...` with a checked pattern such as:

```rust
let (rest, val) = Self::parse_be(tlv, tl.typ)?;
if !rest.is_empty() {
    return Err(...);
}
```

Apply the same rule to TLVs, sub-TLVs, and sub2-TLVs.

### 3. `emit_sub_tlvs()` writes more data than its back-patched length allows

- **Severity:** Medium
- **Files:**
  - `src/util.rs`
  - call sites in `src/sub/prefix.rs` and `src/sub/neigh.rs`

Current helper:

```rust
pub fn emit_sub_tlvs(buf: &mut BytesMut, emit_fn: impl FnOnce(&mut BytesMut)) {
    buf.put_u8(0);
    let pp = buf.len();
    emit_fn(buf);
    buf[pp - 1] = (buf.len() - pp).min(255) as u8;
}
```

- **Problem:** When `emit_fn()` writes more than 255 bytes, the length byte is
  clamped to `255` but the payload itself is not truncated or rejected. The
  resulting encoding contains hidden trailing bytes beyond the declared nested
  length.
- **Impact:** A local caller can emit malformed packets that peer parsers may
  interpret inconsistently. This is not currently reachable from untrusted
  network input alone, but it is still an encoder correctness issue in a packet
  construction library.
- **Recommendation:** Make this path checked rather than saturating:
  - reject nested payloads larger than 255 bytes, or
  - truncate the emitted nested bytes to 255 before patching the length field.

## Residual Hardening Issues

These issues are lower severity because they are tied to local packet
construction rather than parsing untrusted wire input:

- unchecked `u8` length arithmetic remains in a few places, including
  `IsisTlvIsNeighbor::len()` in `src/parser.rs`,
  `IsisTlvLspEntries::len()` in `src/parser.rs`,
  `IsisTlvMultiTopology::len()` in `src/sub/prefix.rs`, and
  `IsisSubAsla::len()` in `src/sub/neigh.rs`.
- several `sub_len()` helpers sum `u8` lengths directly. Oversized collections
  can therefore wrap in release builds and produce malformed wire output.

Recommended follow-up:

1. replace `as u8` casts with `u8::try_from(...)` where oversize data should be
   rejected.
2. use `checked_add()` or compute lengths in `usize` and convert once at the
   boundary.
3. add regression tests for oversized local constructors.

## Recommended Priority

### Priority 1

1. Enforce PDU wire boundaries using the declared PDU lengths.
2. Make all TLV/sub-TLV parsers require full consumption of their bounded
   payloads.

### Priority 2

3. Change `emit_sub_tlvs()` from saturating behavior to checked behavior.
4. Convert the remaining local-construction length arithmetic to checked
   arithmetic.

### Priority 3

5. Add negative tests for:
   - TLVs with valid prefixes and trailing garbage
   - PDUs with extra TLVs beyond declared `pdu_len`
   - oversized nested sub-TLV emission
6. Add fuzzing around `isis_packet::parse()` with malformed length fields and
   partially valid nested TLVs.

## Verification

The current tree was validated with:

```sh
cargo test -p isis-packet
```

All tests passed at the time of this revision.
