# isis-packet Security Audit: Buffer Overrun and Crash Issues

**Audit date:** 2026-03-19
**Crate version:** 0.9.0
**nom version:** 8.0.0

## Summary

Found **10 issues** across the crate. Two are critical crash bugs reachable
from crafted network input. The most common remaining patterns are unchecked
prefix-length values leading to slice panics, ignored sub-TLV length fields,
`as u8` cast truncation in length calculations, and data-loss bugs in
serialization round-trips.

### Previously reported issues now fixed

The following issues from the prior audit have been addressed:
- `is_valid_checksum` now checks `input.len() < 12` before indexing.
- `IsisPacket::emit` now checks `buf.len() >= 26` before writing LSP checksum.
- `checksum_calc` now returns `[0, 0]` when `data.len() < 13`.
- All `split_at()` calls have been replaced with `packet_utils::safe_split_at()`
  which returns `Err::Incomplete` instead of panicking.
- `ptake` now validates `prefixlen <= 32` before computing `psize` (issue 1).
- `ptakev6` now validates `prefixlen <= 128` before computing `psize` (issue 2).

---

## Critical (CRASH / Panic from malformed packets)

### 1. `ptake` panics on IPv4 prefix length > 32 — **FIXED**

- **File:** `src/sub/prefix.rs:493-507`
- **Code:**
  ```rust
  pub fn ptake(input: &[u8], prefixlen: u8) -> IResult<&[u8], Ipv4Net> {
      // ...
      let psize = psize(prefixlen);      // e.g., prefixlen=33 → psize=5
      // ...
      let mut addr = [0u8; 4];
      addr[..psize].copy_from_slice(&input[..psize]);  // PANIC: 5 > 4
  ```
- **Problem:** `psize(33)` returns 5, but `addr` is `[u8; 4]`. The slice
  `addr[..5]` panics with index-out-of-bounds.
- **Trigger:** An IS-IS Extended IP Reachability TLV (type 135) or MT IP
  Reachability TLV (type 235) with a crafted `prefixlen` field in the
  6-bit `Ipv4ControlInfo` bitfield set to any value 33–63. The bitfield
  allows values 0–63.
- **Impact:** Daemon crash from a single crafted LSP received from any
  IS-IS neighbor (or injected on the wire).
- **Fix:** Validate `prefixlen <= 32` before computing `psize`, or clamp
  `psize` to `min(psize, 4)`.

### 2. `ptakev6` panics on IPv6 prefix length > 128 — **FIXED**

- **File:** `src/sub/prefix.rs:510-524`
- **Code:**
  ```rust
  pub fn ptakev6(input: &[u8], prefixlen: u8) -> IResult<&[u8], Ipv6Net> {
      // ...
      let psize = psize(prefixlen);      // e.g., prefixlen=129 → psize=17
      // ...
      let mut addr = [0u8; 16];
      addr[..psize].copy_from_slice(&input[..psize]);  // PANIC: 17 > 16
  ```
- **Problem:** Same pattern as issue 1. `psize(129)` returns 17, but `addr`
  is `[u8; 16]`.
- **Trigger:** An IS-IS IPv6 Reachability TLV (type 236), MT IPv6
  Reachability TLV (type 237), or SRv6 Locator TLV (type 27) with a
  `prefixlen` byte in range 129–255.
- **Impact:** Daemon crash from a single crafted LSP.
- **Fix:** Validate `prefixlen <= 128` before computing `psize`, or clamp
  `psize` to `min(psize, 16)`.

---

## High (Data corruption / incorrect wire encoding)

### 3. SRv6 `sub2_len` field is ignored during parsing

- **Files:**
  - `src/sub/neigh.rs:488-502` (`IsisSubSrv6EndXSid::parse_be`)
  - `src/sub/neigh.rs:553-568` (`IsisSubSrv6LanEndXSid::parse_be`)
  - `src/sub/prefix.rs:87-100` (`IsisSubSrv6EndSid::parse_be`)
- **Code (representative):**
  ```rust
  let (input, sub2_len) = be_u8(input)?;
  // sub2_len is read but NOT used to bound parsing
  if sub2_len == 0 {
      return Ok((input, sub));
  }
  let (_, sub2s) = many0_complete(IsisSub2Tlv::parse_subs).parse(input)?;
  ```
- **Problem:** The `sub2_len` field is read from the wire but never passed
  to `safe_split_at()` to bound sub-sub-TLV parsing. Instead,
  `many0_complete` consumes all remaining bytes in the parent-bounded
  slice. If the parent TLV has additional data after the sub2 region,
  it would be incorrectly parsed as sub2 TLVs.
- **Mitigation:** The parent `parse_subs` call already bounds input via
  `safe_split_at(input, cl.len)`, which limits the blast radius. However,
  the sub2 boundary within that bounded region is not enforced.
- **Fix:** Add `let (input, sub2_data) = safe_split_at(input, sub2_len as usize)?;`
  before parsing sub2 TLVs.

### 4. `IsisTlvUnknown` loses TLV payload data on parse

- **File:** `src/parser.rs:1005-1012`
- **Code:**
  ```rust
  pub fn parse_tlv(input: &[u8], tl: IsisTypeLen) -> IResult<&[u8], Self> {
      let tlv = IsisTlvUnknown {
          typ: tl.typ,
          len: tl.len,
          values: Vec::new(),   // ← payload data is NOT preserved
      };
      Ok((input, tlv))
  }
  ```
- **Problem:** The `input` parameter contains `tl.len` bytes of TLV payload,
  but `values` is set to an empty Vec. When re-emitted via `emit()`, the
  TLV is written with type + length + zero payload bytes, producing a
  malformed packet.
- **Impact:** Any IS-IS packet containing unknown TLVs will be corrupted if
  parsed and re-serialized (e.g., LSP flooding).
- **Fix:** `values: input.to_vec()`.

### 5. `IsisTlvLspEntries::len()` uses `mem::size_of` instead of wire size

- **File:** `src/parser.rs:706-707`
- **Code:**
  ```rust
  fn len(&self) -> u8 {
      (self.entries.len() * std::mem::size_of::<IsisLspEntry>()) as u8
  }
  ```
- **Problem:** `mem::size_of::<IsisLspEntry>()` returns the Rust struct's
  in-memory size, which may include alignment padding and differs from
  the 16-byte wire format (hold_time:2 + lsp_id:8 + seq_number:4 +
  checksum:2). Without `#[repr(C)]` or `#[repr(packed)]`, the compiler
  may reorder fields and add padding.
- **Impact:** If `size_of` ever returns a value other than 16, the TLV
  length field will be wrong, causing incorrect packet encoding.
- **Fix:** Use a constant `const LSP_ENTRY_WIRE_SIZE: usize = 16;` instead
  of `mem::size_of`.

---

## Medium

### 6. `as u8` silent truncation in multiple `len()` methods

Multiple `len()` methods use `as u8` casts that silently wrap on overflow:

| File | Line | Expression |
|------|------|------------|
| `src/parser.rs:593` | `(self.area_addr.len() + 1) as u8` |
| `src/parser.rs:635` | `(self.neighbors.len() * 6) as u8` |
| `src/parser.rs:662` | `self.padding.len() as u8` |
| `src/parser.rs:765` | `self.nlpids.len() as u8` |
| `src/parser.rs:840` | `self.hostname.len() as u8` |
| `src/sub/neigh.rs:274` | `(self.groups.len() * 4) as u8` |
| `src/sub/cap.rs:141` | `self.algo.len() as u8` |

- **Problem:** IS-IS TLV length is u8 (max 255). If programmatic
  construction creates data exceeding 255 bytes, the cast wraps silently,
  causing the emitted TLV length to be incorrect. Downstream parsers
  would then read wrong boundaries.
- **Trigger:** Constructing TLVs programmatically with many entries
  (e.g., 43+ IS-Neighbors, 16+ LSP entries).
- **Fix:** Use `u8::try_from(...).expect("TLV exceeds max length")` or
  split into multiple TLVs when the total exceeds 255.

### 7. `IsisTlvHostname::parse_be` does not consume input

- **File:** `src/parser.rs:1031-1037`
- **Code:**
  ```rust
  fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
      let hostname = Self {
          hostname: String::from_utf8_lossy(input).to_string(),
      };
      Ok((input, hostname))  // returns unconsumed input
  }
  ```
- **Problem:** The function reads the entire input into `hostname` but
  returns the original `input` as remaining (should return `&[]`).
  This is safe because the caller (`parse_tlv`) discards the remaining
  bytes with `_`, but it breaks the nom parser contract.
- **Fix:** `Ok((&input[input.len()..], hostname))` or `Ok((&[], hostname))`.

### 8. Back-patching emit with `as u8` truncation

- **Files:**
  - `src/sub/neigh.rs:529` (`IsisSubSrv6EndXSid::emit`)
  - `src/sub/neigh.rs:596` (`IsisSubSrv6LanEndXSid::emit`)
  - `src/sub/prefix.rs:124` (`IsisSubSrv6EndSid::emit`)
  - `src/sub/prefix.rs:622` (`Srv6Locator::emit`)
- **Code:**
  ```rust
  buf.put_u8(0);
  let pp = buf.len();
  for sub2 in &self.sub2s { sub2.emit(buf); }
  buf[pp - 1] = (buf.len() - pp) as u8;
  ```
- **Problem:** `(buf.len() - pp) as u8` silently truncates if sub-sub-TLV
  data exceeds 255 bytes, writing an incorrect length.
- **Note:** `pp` is always > 0 here because preceding writes ensure the
  buffer is non-empty, so `pp - 1` does not underflow.
- **Fix:** Assert or check that `buf.len() - pp <= 255`.

---

## Low

### 9. `SidLabelValue::parse_be` error reporting for unexpected sizes

- **File:** `src/parser.rs:1089-1103`
- **Code:**
  ```rust
  fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
      match input.len() {
          3 => { /* Label */ }
          4 => { /* Index */ }
          _ => Err(Err::Incomplete(Needed::new(input.len()))),
      }
  }
  ```
- **Problem:** For `input.len() == 0`, `Needed::new(0)` returns
  `Needed::Unknown` (not a crash in nom 8, but semantically wrong).
  For `input.len() > 4`, the error says "need N more bytes" where
  N is the current length, which is misleading. The error type should
  be `Err::Error`, not `Err::Incomplete`, since the data is malformed,
  not incomplete.
- **Fix:** Return `Err::Error(nom::error::make_error(input, ErrorKind::LengthValue))`.

### 10. `Ipv4Net::new().unwrap()` in prefix parsers

- **File:** `src/sub/prefix.rs:495,513,504,521`
- **Code:**
  ```rust
  Ipv4Net::new(Ipv4Addr::UNSPECIFIED, 0).unwrap()
  Ipv6Net::new(Ipv6Addr::UNSPECIFIED, 0).unwrap()
  ```
- **Problem:** `.unwrap()` is used, though these specific calls are
  guaranteed to succeed (UNSPECIFIED with prefix_len=0 is always valid).
- **Note:** The `Ipv4Net::new` calls for parsed addresses (lines 504, 521)
  use `let Ok(prefix) = ... else { return Err(...) }`, which is correct.
- **Fix:** No action needed, but consider `expect("UNSPECIFIED/0 is always valid")`
  for documentation.

---

## Recommendations

### Priority 1 — Fix before next release
1. Add prefix-length validation in `ptake` (≤ 32) and `ptakev6` (≤ 128)
   to prevent crash from crafted LSPs. This is remotely exploitable.
2. Use `safe_split_at(input, sub2_len)` in SRv6 sub2 parsing to honor the
   wire-format length field.

### Priority 2 — Address soon
3. Preserve unknown TLV payload in `IsisTlvUnknown::parse_tlv` to prevent
   data loss on re-serialization.
4. Replace `mem::size_of::<IsisLspEntry>()` with a wire-format constant (16).
5. Fix `IsisTlvHostname::parse_be` to consume input properly.

### Priority 3 — Harden
6. Replace `as u8` casts in `len()` methods with checked arithmetic.
7. Add `debug_assert!` guards on back-patching emit code for sub2 length.
8. Consider fuzz testing with `cargo-fuzz` on `isis_packet::parse()` to
   catch further edge cases in the nom-based parser chain.
