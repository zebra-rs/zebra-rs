# isis-packet - Would-be Changes (Buffer Overrun / Underrun)

This file records the **would-be fixes** identified by the 2026-08-07 buffer overrun/underrun investigation of `crates/isis-packet/src`. No code was changed; this is documentation of the exact edits that would be made and their impact.

Baseline: no prior `AUDIT.md` for this crate; invariants mirrored from `crates/bgp-packet/AUDIT.md` (every length-prefixed slice bounded with `safe_split_at`, every TLV loop makes progress, no `unwrap` reachable from wire).

## Scope

`crates/isis-packet/src` — `parser.rs`, `util.rs`, `sub/{mod,neigh,prefix,cap,restart,unknown}`, `srlg.rs`, `checksum.rs`, `padding.rs`, `nsap.rs`, `typ.rs`, `tlv_type.rs`. Verification was static (`search`/`read_file`) only.

## Summary

No classic memory overrun (`unsafe`, raw `split_at`, unchecked `&input[x..y]`). Every TLV/sub-TLV length is bounded with `packet_utils::safe_split_at` (`parser.rs:1593`, `sub/mod.rs:21`, `sub/prefix.rs:915`, `util.rs:20`). Remaining gaps are logical framing: unvalidated trailing bytes inside a `len`-bounded slice, emit-side `buf.len() as u16` wrap, and `while len>=4` leftover tolerance.

---

## Would-be changes

### 1. `src/parser.rs:339` + `415-509` - PDU `pdu_len as u16` wraps on emit (all PDUs)

**Current:**
```rust
let pdu_len: u16 = buf.len() as u16;
BigEndian::write_u16(&mut buf[pp..pp+2], pdu_len);
```
in `IsisLsp::emit`, `IsisHello::emit`, `IsisP2pHello::emit`, `IsisCsnp::emit`, `IsisPsnp::emit`

**Would-be:**
```rust
let pdu_len = u16::try_from(buf.len()).map_err(|_| TooLong{field:"pdu_len", len: buf.len()})?;
// or debug_assert!(buf.len()<=65535) + fallible emit returning Result
BigEndian::write_u16(&mut buf[pp..pp+2], pdu_len);
```
**Impact:** Large LSP/CSNP with many TLVs (>65535B) would wrap `pdu_len` and desync peer's `pdu_len` framing. Latent - bounded by LSP MTU (~1492) in practice; makes emit fallible.

### 2. `src/parser.rs:104-106` - checksum emit writes at fixed offset without re-validating PDU length

**Current:**
```rust
if self.pdu_type.is_lsp() && buf.len() >= 26 {
    let checksum = checksum_calc(&buf[12..]);
    buf[24..26].copy_from_slice(&checksum);
}
```
**Would-be:** No buffer overrun today (`>=26` guards `24..26`, `12..` on valid LSP is safe), but clarify intent and prevent future drift if LSP header grows: compute offsets from constants (`ISIS_HDR=8`, `LSP_CHECKSUM_OFF=8+2+2+8+4`) and add `debug_assert!(buf.len()>= header+26)`. No code change required for safety.

### 3. `src/parser.rs:1590` - `IsisTlv::parse_tlv` accepts trailing bytes inside TLV value

**Current:**
```rust
let (input, tl) = IsisTypeLen::parse_be(input)?;
let (input, tlv) = safe_split_at(input, tl.len as usize)?;
if tl.typ.is_known() { if let Ok((_, val)) = Self::parse_be(tlv, tl.typ) { return Ok((input, val)); } }
let (_, val) = IsisTlvUnknown::parse_tlv(tlv, tl)?;
Ok((input, Self::Unknown(val)))
```
`Self::parse_be(tlv,...)` may consume only prefix of `tlv` (e.g. `Srlg` with `while len>=4` leaves 1-3 leftover) and still be considered `Ok`. Remaining bytes inside the `len`-bounded slice are silently ignored.

**Would-be:**
```rust
if let Ok((rest, val)) = Self::parse_be(tlv, tl.typ) {
    if !rest.is_empty() { return Unknown degrade: Err -> Unknown with bytes preserved }
    return Ok((input, val));
}
```
Same for the `Unknown` degrade path - reject non-empty `rest` inside known TLV and degrade to `Unknown` sobytes are preserved and no phantom TLV walk.

**Impact:** Prevents malformed TLV (e.g. truncated SRLG value) from being accepted as valid and hiding desync.

### 4. `src/srlg.rs:79,141` - SRLG value loop ignores 1-3 trailing bytes

**Current:**
```rust
while input.len() >= 4 { let (rest, v)=be_u32(input)?; values.push(v); input=rest; }
Ok((input, Self{..., values})) // leftover input (0..3 bytes) returned as rest, accepted by caller
```
Caller `parse_be` was invoked on `tlv` slice already bounded by `len`; wrapper `parse_tlv` above ignores `rest`.

**Would-be:**
```rust
while input.len() >= 4 { ... }
if !input.is_empty() { return Err(LengthValue); } // not multiple of 4
Ok((input, ...))
```
**Impact:** Rejects 1-3 byte overhang instead of silently dropping.

### 5. `src/util.rs:12-23` - `parse_sub_block` / sub-TLV blocks ignore trailing bytes

**Current:**
```rust
let (input, sublen)=be_u8(input)?;
let (input, sub)=safe_split_at(input, sublen as usize)?;
let (_, subs)=many0_complete(parse_one).parse(sub)?;
Ok((input, subs))
```
`many0_complete` stops at first error, returning remainder; `rest` not checked.

**Would-be:**
```rust
let (input, sublen)=be_u8(input)?;
if sublen==0 { return Ok((input, Vec::new())); }
let (input, sub)=safe_split_at(input, sublen as usize)?;
let (rest, subs)=many0_complete(parse_one).parse(sub)?;
if !rest.is_empty() { return Err(LengthValue); }
Ok((input, subs))
```
Applies to `src/sub/neigh.rs:224` (mt, subs), `src/sub/prefix.rs:115` etc. Prevents a sub-block with 1 trailing garbage byte from being accepted.

### 6. `src/util.rs:35-46` - `emit_sub_tlvs` truncates in release instead of error

**Current:** `debug_assert!(block<=255)` then `buf.truncate(pp+block.min(255))`.

**Would-be:** Make fallible and return `Err(TooLong)` in release as well, or keep truncation but log. Matches `bgp-packet` F2 rationale - `block.min(255)` keeps length byte and data in sync (no framing desync), but caller should split sub-TLVs across entries instead of truncating. No buffer overrun; decision is whether silent truncation is acceptable.

### 7. `src/parser.rs:1344` - `IsisTlvP2p3Way::parse_be` positional optionals leave trailing bytes inside TLV

The parser uses `if input.len()>=4 { be_u32 }` cascade. If extra bytes beyond the 1-15 byte valid shape remain (e.g. 2 extra bytes), they become leftover inside the TLV slice. Combined with #3, accepted as valid. Would-be fix is #3's rest check, or make `P2p3Way::parse_be` reject `!input.is_empty()` after the three optionals.

### 8. `src/parser.rs:849` vs others - `IsisTlvLspEntries::len` already documents wrap hazard

`len()` does `(entries.len()*16) as u8` with `MAX_ENTRIES=15` documented. This is intentional counterpart to bgp-packet's F2 - caller must shard. No would-be change, but preserve `wire_len()` unsaturated reporting (already done `wire_len()` at `parser.rs:593`) as invariant.

### 9. `src/checksum.rs:1-5` - `is_valid_checksum` is safe

`if input.len()<12 { false }` before `&input[12..]` and `calc_fletcher16(&input[12..])` handles empty suffix. No change.

### 10. `src/nsap.rs:114` - `sys_id_pair` panic already fixed

Previous `hex::decode` of 2-char group yielding 1 octet and indexing `[1]` panicked; now uses `try_into` -> error. No further change.

---

## Invariants to preserve (mirrored from bgp-packet)

1. Every length-prefixed slice with `safe_split_at`, never raw `split_at` / `&input[x..y]`.
2. After parsing inside bounded slice, reject `!rest.is_empty()` with `LengthValue` - degrade known TLV to `Unknown` with bytes preserved.
3. Emit length bytes derived from a checked `try_from` or clamped `wire_len`, never bare `as u8/u16` on unbounded length.
4. Sub-TLV blocks: `safe_split_at(sublen)` then `many0_complete` must verify `rest.is_empty()`.
