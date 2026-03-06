# ospf-packet Security Audit: Buffer Overrun and Crash Issues

## Summary

Found **7 issues** in the crate. **3 critical/high issues have been fixed.**
The most critical were unchecked slice indexing in checksum/validation functions
and integer overflow in LSA length calculations.

## Critical (CRASH/Panic from malformed packets)

### 1. Unchecked slice indexing in validate_checksum()

- **File:** `src/parser.rs:946-947`
- **Code:**
  ```rust
  pub fn validate_checksum(input: &[u8]) -> IResult<&[u8], ()> {
      const AUTH_RANGE: std::ops::Range<usize> = 16..24;

      let mut cksum = Checksum::new();
      cksum.add_bytes(&input[0..AUTH_RANGE.start]);  // assumes input.len() >= 16
      cksum.add_bytes(&input[AUTH_RANGE.end..]);      // assumes input.len() >= 24
      // ...
  }
  ```
- **Problem:** No bounds check before slicing. `input[24..]` panics if
  `input.len() < 24`.
- **Trigger:** Any OSPF packet shorter than 24 bytes.
- **Fix:** Return error if `input.len() < 24`. **FIXED.**

### 2. Unchecked buffer indexing in verify_checksum()

- **File:** `src/parser.rs:408-413`
- **Code:**
  ```rust
  pub fn verify_checksum(&self) -> bool {
      let mut buf = BytesMut::with_capacity(self.h.length as usize);
      self.h.emit(&mut buf);
      self.emit_lsp(&mut buf);
      if buf.len() < 18 {
          return false;
      }
      buf[16] = 0;  // assumes buf.len() >= 17
      buf[17] = 0;  // assumes buf.len() >= 18
      // ...
  }
  ```
- **Problem:** The guard checks `buf.len() < 18` and returns false, so indices
  16 and 17 are safe. However, if the check is accidentally changed to `< 17`,
  index 17 would panic. The pattern is fragile.
- **Severity:** Low (currently safe due to guard, but fragile).

### 3. Arithmetic underflow in lsa_checksum_calc()

- **File:** `src/parser.rs:459`
- **Code:**
  ```rust
  fn lsa_checksum_calc(data: &[u8], cksum_offset: usize) -> u16 {
      // ...
      let sop = (data.len() - cksum_offset - 1) as i32;
      // ...
  }
  ```
- **Problem:** If `data.len() < cksum_offset + 1`, the subtraction underflows
  (panic in debug, wrap in release). The function is currently only called with
  `cksum_offset = 14` after a `buf.len() >= 18` check, so `data = &buf[2..]`
  has `len >= 16`, making `16 - 14 - 1 = 1` safe. However, the function is
  `pub(crate)` and has no internal validation.
- **Trigger:** Calling `lsa_checksum_calc()` with `data.len() < cksum_offset + 1`.
- **Fix:** Add `assert!(data.len() > cksum_offset)` or return 0 for short data. **FIXED.**

### 4. Unchecked buffer indexing in Ospfv2Packet::emit()

- **File:** `src/parser.rs:70, 76`
- **Code:**
  ```rust
  pub fn emit(&self, buf: &mut BytesMut) {
      buf.put_u8(self.version);
      buf.put_u8(self.typ.into());
      buf.put_u16(self.len);
      // ... payload emit ...
      let len = buf.len() as u16;
      BigEndian::write_u16(&mut buf[2..4], len);           // line 70

      const CHECKSUM_RANGE: std::ops::Range<usize> = 12..14;
      buf[CHECKSUM_RANGE].copy_from_slice(&cksum.checksum()); // line 76
  }
  ```
- **Problem:** `buf[12..14]` assumes the buffer reached at least 14 bytes after
  payload emit. For an empty or minimal payload, the OSPF header itself is
  24 bytes (version + type + length + router_id + area_id + checksum + autype +
  auth), so this is safe in practice. But if a payload variant emits nothing and
  the header is incomplete, line 76 could panic.
- **Severity:** Low (header emit guarantees >= 24 bytes in normal use).

## High (Integer overflow / silent corruption)

### 5. Integer overflow in lsa_len() calculations

Multiple `lsa_len()` methods multiply `Vec::len()` by a constant and add a
base, all as `u16`. These overflow silently if the count is large enough.

| File | Line | Expression | Overflows when |
|------|------|------------|----------------|
| `src/parser.rs` | 589 | `4 + links.iter().map(\|l\| l.lsa_len()).sum::<u16>()` | Total link size > 65531 |
| `src/parser.rs` | 632 | `12 + toses.len() as u16 * 4` | toses.len() > 16382 |
| `src/parser.rs` | 657 | `4 + attached_routers.len() as u16 * 4` | routers.len() > 16382 |
| `src/parser.rs` | 697 | `8 + tos_routes.len() as u16 * 4` | tos_routes.len() > 16381 |
| `src/parser.rs` | 760 | `16 + tos_list.len() as u16 * 12` | tos_list.len() > 5459 |
| `src/parser.rs` | 781 | `16 + tos_list.len() as u16 * 12` | tos_list.len() > 5459 |

- **Problem:** If the count is large enough, the u16 multiplication wraps
  around, producing a small length value. This causes the emitted LSA to have
  an incorrect length field, which could cause downstream parsers to read beyond
  or short of the actual data.
- **Trigger:** OSPF LSA with very large TOS or router lists (unlikely in
  practice but possible with crafted packets). The parser creates these Vecs
  from packet data using `many0_complete`, which could produce arbitrarily
  large vectors from malformed length fields.
- **Fix:** Use `checked_mul()` / `checked_add()` or cap Vec sizes during
  parsing.

### 6. Debug println left in RouterInfoTlv::parse_tlv()

- **File:** `src/parser.rs:903`
- **Code:**
  ```rust
  println!("XXX RouteInfoTlvType {:?} {}", typ, tl.len);
  ```
- **Problem:** Debug print left in production code. Not a security issue but
  causes unnecessary I/O and leaks internal parsing state.
- **Fix:** Remove the `println!`. **FIXED.**

## Medium

### 7. Large allocation from untrusted LSA length

- **File:** `src/parser.rs:524`
- **Code:**
  ```rust
  let payload_length = total_length.saturating_sub(20) as usize;
  let (remaining_input, payload_input) = take(payload_length)(input)?;
  ```
- **Problem:** `total_length` comes from the LSA header (untrusted). While
  `saturating_sub` prevents underflow and `take()` returns `Incomplete` if
  insufficient data, a length of 65535 causes nom to attempt to consume 65515
  bytes. This is bounded by actual input size but could cause large intermediate
  allocations in `UnknownLsa { data: payload_input.to_vec() }`.
- **Trigger:** OSPF LSA with `length = 65535` in a large packet.
- **Fix:** Cap `payload_length` to a reasonable maximum (e.g., MTU size).

## Recommendations

1. **Immediate:** Add bounds check in `validate_checksum()` — return error if
   `input.len() < 24`.
2. **Immediate:** Add guard in `lsa_checksum_calc()` for
   `data.len() > cksum_offset`.
3. **High priority:** Use checked arithmetic in `lsa_len()` methods to prevent
   u16 overflow.
4. **Cleanup:** Remove debug `println!("XXX ...")` from `parse_tlv()`.
5. **General:** Consider capping parsed Vec sizes to prevent memory exhaustion
   from malformed packets.
