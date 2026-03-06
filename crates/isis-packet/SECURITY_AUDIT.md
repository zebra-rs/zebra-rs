# isis-packet Security Audit: Buffer Overrun and Crash Issues

## Summary

Found **9 issues** across the crate. The most common patterns are unchecked
`split_at()` calls with untrusted TLV lengths, unchecked slice indexing in
checksum code, and u8 cast truncation in length calculations.

## Critical (CRASH/Panic from malformed packets)

### 1. Unchecked buffer indexing in checksum validation

- **File:** `src/checksum.rs:2`
- **Code:**
  ```rust
  pub fn is_valid_checksum(input: &[u8]) -> bool {
      fletcher::calc_fletcher16(&input[12..]) == 0
  }
  ```
- **Problem:** Direct slice index `input[12..]` panics if `input.len() < 12`.
- **Trigger:** Any IS-IS packet smaller than 12 bytes.
- **Fix:** Return `false` if `input.len() < 12`.

### 2. Unchecked buffer indexing in LSP checksum writing

- **File:** `src/parser.rs:98-101`
- **Code:**
  ```rust
  if self.pdu_type.is_lsp() {
      let checksum = checksum_calc(&buf[12..]);
      buf[24..26].copy_from_slice(&checksum);
  }
  ```
- **Problem:** No verification that `buf` has at least 26 bytes. Panics on
  `buf[24..26]` if buffer is too small.
- **Trigger:** Emitting an LSP packet with minimal or empty TLV content.
- **Fix:** Assert or check `buf.len() >= 26` before indexing.

### 3. Arithmetic underflow in checksum calculation

- **File:** `src/checksum.rs:10`
- **Code:**
  ```rust
  let sop = data.len() as u16 - 13;
  ```
- **Problem:** Unchecked subtraction. If `data.len() < 13`, this underflows
  (panic in debug, wraps in release).
- **Trigger:** Checksum calculation on data shorter than 13 bytes.
- **Fix:** Check `data.len() >= 13` before subtraction.

### 4. Unchecked split_at() with untrusted TLV lengths

Multiple locations use `split_at()` with lengths from packet data without
validating the length fits in the remaining input. All panic if the length
exceeds `input.len()`.

| File | Line | Context |
|------|------|---------|
| `src/sub/neigh.rs` | 84 | Sub-TLV length in Extended IS Reach |
| `src/sub/prefix.rs` | 169 | Sub-TLV length in Extended IP Reach |
| `src/sub/prefix.rs` | 205 | Sub-TLV length in MT IP Reach |
| `src/sub/prefix.rs` | 549 | Sub-TLV length in Extended IP Reach Entry |
| `src/sub/prefix.rs` | 573 | Sub-TLV length in IPv6 Reach Entry |
| `src/sub/prefix.rs` | 650 | Sub-TLV length in SRv6 Locator |
| `src/sub/cap.rs` | 40 | Sub-TLV length in Router Capability |
| `src/parser.rs` | 1111 | SID/Label value parsing |

- **Common pattern:**
  ```rust
  let (input, sublen) = be_u8(input)?;
  let (sub, input) = input.split_at(sublen as usize);  // panics!
  ```
- **Trigger:** IS-IS TLV with sub-TLV length field greater than remaining data.
- **Fix:** Check `input.len() >= sublen as usize` before `split_at()`, or use
  `nom::bytes::complete::take()`.

## High (Panic or silent corruption)

### 5. Cast truncation in TLV length calculations

Multiple `len()` methods cast to `u8`, silently truncating values > 255.

| File | Line | Expression |
|------|------|------------|
| `src/parser.rs` | 593 | `(self.area_addr.len() + 1) as u8` |
| `src/parser.rs` | 635 | `(self.neighbors.len() * 6) as u8` |
| `src/parser.rs` | 707 | `(self.entries.len() * size_of::<IsisLspEntry>()) as u8` |
| `src/parser.rs` | 765 | `(self.protocols.len()) as u8` |
| `src/parser.rs` | 840 | `(self.addrs.len() * 4) as u8` |

- **Problem:** If `neighbors.len() * 6 >= 256`, the length wraps to a small
  value. Downstream code relying on the length will read/write beyond intended
  boundaries.
- **Trigger:** IS-IS LSP with many neighbors (43+), many LSP entries (13+), etc.
- **Fix:** Use checked arithmetic or `u16` length fields. IS-IS TLV length is
  u8, so split into multiple TLVs when exceeding 255 bytes.

### 6. Unsafe buffer index modification in emit code

- **Files:** `src/sub/prefix.rs:124`, `src/sub/neigh.rs:408-413, 475-480`
- **Code:**
  ```rust
  buf.put_u8(0);
  let pp = buf.len();
  for sub2 in &self.sub2s {
      sub2.emit(buf);
  }
  buf[pp - 1] = (buf.len() - pp) as u8;
  ```
- **Problem:** If `pp == 0`, then `buf[pp - 1]` causes underflow/out-of-bounds.
  While unlikely in normal operation, this is unsafe defensively.
- **Trigger:** Theoretically possible if emit is called on a fresh buffer with
  no prior writes.
- **Fix:** Assert `pp > 0` or restructure to avoid back-patching.

## Medium

### 7. Unsafe unwrap on network address creation

- **File:** `src/sub/prefix.rs:501, 518`
- **Code:**
  ```rust
  return Ok((input, Ipv4Net::new(Ipv4Addr::UNSPECIFIED, 0).unwrap()));
  return Ok((input, Ipv6Net::new(Ipv6Addr::UNSPECIFIED, 0).unwrap()));
  ```
- **Problem:** `.unwrap()` on `Ipv4Net::new()`. These specific cases
  (UNSPECIFIED, prefix_len=0) are guaranteed to succeed, but the pattern is
  fragile.
- **Fix:** Use `Ipv4Net::default()` or document the safety invariant.

### 8. Potential DoS via large Vec allocation in padding

- **File:** `src/padding.rs:44, 100`
- **Code:**
  ```rust
  padding: vec![0u8; len],
  ```
- **Problem:** `len` could be influenced by packet data. Mitigated by MTU
  checks earlier in the code path.
- **Severity:** Low — MTU validation limits the allocation size.

## Recommendations

1. **Immediate:** Add bounds checks before all `split_at()` calls — replace
   with `nom::bytes::complete::take()` or explicit length validation.
2. **Immediate:** Guard `checksum.rs` against short inputs (`< 12` and `< 13`
   bytes).
3. **High priority:** Add bounds check before `buf[24..26]` in LSP emit.
4. **High priority:** Address u8 cast truncation in `len()` methods — either
   split large TLVs or use checked arithmetic with error reporting.
5. **General:** Replace `.unwrap()` with proper error propagation in parser code.
