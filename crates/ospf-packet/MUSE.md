# ospf-packet - Would-be Changes (Buffer Overrun / Underrun)

This file records the **would-be fixes** identified by the 2026-08-07 buffer overrun/underrun investigation of `crates/ospf-packet/src`. No code was changed; this is documentation of the exact edits that would be made and their impact.

Baseline: no prior `AUDIT.md` for this crate; invariants mirrored from `crates/bgp-packet/AUDIT.md` and `crates/isis-packet/MUSE.md` (every length-prefixed slice bounded with `safe_split_at`, no `unwrap` reachable from wire, length fields validated).

## Scope

`crates/ospf-packet/src` — `parser.rs` (OSPFv2), `v3.rs` (OSPFv3), `typ.rs`, `util.rs`. Verification static (`search`/`read_file`) only. Shell sandbox was down.

## Summary

No classic memory overrun (`unsafe`, raw `split_at`, unchecked `&input[x..y]`). Every TLV is bounded with `packet_utils::safe_split_at` (`parser.rs:1191,1362,1554,1626,1980,2064,2160,2621`, `v3.rs:1849,2224,2498` etc.), and every `take` / `BigEndian::read_*` is preceded by length checks. Remaining gaps are logical framing: `saturating_sub`-masked underrun, emit-side `as u16` / `buf.len() as u16` wrap (clamped with `min(u16::MAX)`), and `BigEndian::write_u16` on unproven length.

---

## Would-be changes

### 1. `src/parser.rs:702` - LSA payload length masks underrun (`saturating_sub`)

**Current:**
```rust
let payload_length = total_length.saturating_sub(20) as usize;
let (remaining_input, payload_input) = take(payload_length)(input)?;
```

**Would-be:**
```rust
let payload_length = total_length.checked_sub(20).ok_or(LengthValue)? as usize;
// also verify total_length >= 20 and payload_length <= input.len() already checked by take
```
Applies identically to `src/v3.rs:2819` (`saturating_sub(OSPFV3_LSA_HEADER_LEN)`) and the 20-byte header constant.

**Impact:** `total_length <20` (malformed header) now errors instead of `take(0)` succeeding and a 0-body LSA being parsed as valid.

### 2. `src/parser.rs:68-119` + `src/v3.rs:319-336,303-336` - packet `len` emit truncates instead of failing

**Current:**
```rust
debug_assert!(buf.len() <= u16::MAX as usize);
let len = buf.len().min(u16::MAX as usize) as u16;
BigEndian::write_u16(&mut buf[2..4], len);
```
in `Ospfv2Packet::emit`, `Ospfv3Packet::emit`, and per-LSA `h.length` assignments (`lsa_len()+20 as u16`, `lsa_len()` helpers at `parser.rs:828,866,891,931,994,1401`, `v3.rs:2800,3022`).

**Would-be:** Make emit fallible:
```rust
let len = u16::try_from(buf.len()).map_err(|_| TooLong{field:"packet len", len: buf.len()})?;
BigEndian::write_u16(&mut buf[2..4], len);
```
And `OspfLsa::update` / `Ospfv3Lsa::update` -> `Result<(), TooLong>`. `v3.rs:1071` `num: self.prefixes.len().min(u16::MAX) as u16` and other `as u16` at `parser.rs:1225,1251,1401,1723,1793,2195` etc. become `u16::try_from`.

**Impact:** >65535B packet no longer wraps length field to small value and desyncs peer framing. Latent - OSPF MTU bounds make it rare, same class as `bgp-packet` F2 and `isis-packet` pdu_len.

### 3. `src/parser.rs:95,113,2855` + `src/v3.rs:310,334` - `BigEndian::write_u16(&mut buf[off..off+2])` without length proof

**Current:** `BigEndian::write_u16(&mut buf[2..4], len)` assumes `buf.len()>=4` (true after header+payload emit), and `buf[16..18].copy_from_slice` assumes `buf.len()>=18`. Guarded by header write but not proven at type level.

**Would-be:** Add `debug_assert!(buf.len() >= 4)` / `>=18` before write, or use `buf[off..off+2].copy_from_slice(&len.to_be_bytes())` after `if buf.len()<off+2 { return Err }`. No behavior change; documents invariant.

### 4. `src/parser.rs:1191,1362,1554,1979,2064,2621` + `src/v3.rs:1849,2498` - TLV 4-byte padding underrun not checked

**Current:**
```rust
let len = tl.len as usize;
let (input, tlv) = safe_split_at(input, len)?;
...
let padded = (len + 3) & !3;
let (input, _) = take(padded - len)(input)?;
```
If `tl.len` is e.g. 255 but `input` after `safe_split_at` has only `padded-len` trailing pad bytes missing, `take(padded-len)` would return `Incomplete` -> error, which is correct. However `padded - len` arithmetic on `usize` after `len as usize` is safe; the gap is that `tl.len` itself is `u8` (TLV) or `u16` (Extended TLV) and was already bounded by `safe_split_at`, so no overrun. No change, but note invariant: `safe_split_at` is the sole boundary, `take(padded-len)` is on the outer `input` after the TLV slice.

### 5. `src/parser.rs:2244-2247,2399-2402` - ASLA sub-TLV `safe_split_at(sabm_len)` leaves trailing bytes as `subs` input without empty check

**Current:** `safe_split_at(input, sabm_len)` then `many0_complete(AslaSubSubTlv::parse_sub).parse(input)` - not checking `rest.is_empty()` inside the sliced block.

**Would-be:**
```rust
let (input, sabm) = safe_split_at(input, sabm_len as usize)?;
let (input, udabm) = safe_split_at(input, udabm_len as usize)?;
let (rest, subs) = many0_complete(...).parse(input)?;
if !rest.is_empty() { return Err(LengthValue); }
```
Same for `sub/prefix` sub-blocks. Already filed as `isis-packet` #5; OSPF extended prefix/link carries same shape.

### 6. `src/parser.rs:414-432`, `src/v3.rs:2870-2877` - `parse_lsas_with_raw` caps allocation but not trailing bytes

`bounded_capacity` prevents huge allocation from forged `num_adv`, and `for _ in 0..n { OspfLsa::parse_be }` propagates first malformed known LSA per `LspSelector` Unknown fallback. No buffer overrun. Would-be improvement: verify `rest.is_empty()` after loop when caller expects exact `input.len()` consumed (packet body). Currently caller `Ospfv2Packet` via `NomBE` will leave extra bytes as next-packet head if `len` was lying; `parse_v3`'s explicit `pkt_len` slice prevents this for v3.

### 7. `src/v3.rs:120-162` - `parse_v3` trailer probe bounds are safe

`pkt_len` read from `input[2..4]` only after `input.len()>=16`, then `if input.len()>=pkt_len+4 { trailer_len = read_u16 }` checks `16..=1024` and `input.len()>=pkt_len+trailer_len` before `to_vec()` - correct against gigabyte allocation.

---

## Invariants to preserve

1. Every TLV/Extended TLV length via `safe_split_at(len)` never raw `split_at` / `&input[..len]`.
2. After `safe_split_at`, verify no trailing bytes inside the slice (`rest.is_empty()` or degrade to Unknown).
3. Length fields that are `u16` on wire must be emitted via checked `try_from`, not `as u16` / `min(u16::MAX)` truncation.
4. PDU `length_indicator` / `len` validated against `header.len` before slicing (`parse_v3` does, `parser.rs:702` should).
