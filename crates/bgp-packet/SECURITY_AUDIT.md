# bgp-packet Security Audit: Buffer Overrun and Crash Issues

## Summary

Found **9 issues** across the crate, mostly around unchecked `split_at()` calls
and arithmetic on untrusted packet lengths. All issues are potential Denial of
Service vectors when handling malformed or adversarial BGP input.

## Critical (CRASH/Panic from malformed packets)

### 1. Unchecked split_at in NLRI IPv4 parsing

- **File:** `src/attrs/nlri_ipv4.rs:40`
- **Code:**
  ```rust
  let (nlri, input) = input.split_at(length as usize);
  ```
- **Problem:** `split_at()` panics if `length as usize > input.len()`. The
  `length` parameter comes from untrusted BGP packet data with no bounds check.
- **Trigger:** BGP UPDATE with declared NLRI length exceeding actual packet data.
- **Fix:** Check `input.len() >= length as usize` before `split_at()`, or use
  `nom::bytes::complete::take()`.

### 2. Unchecked split_at in Open packet parsing

- **File:** `src/open.rs:64, 74`
- **Code:**
  ```rust
  let (opts, input) = input.split_at(len as usize);       // line 64
  let (opts, input) = input.split_at(header.length as usize); // line 74
  ```
- **Problem:** Both `len` (extended optional parameter length) and
  `header.length` come from untrusted packet data. No bounds check before
  `split_at()`.
- **Trigger:** BGP OPEN with opt_param_len or ext_opt_parm_len larger than
  remaining bytes.
- **Fix:** Validate length against `input.len()` before splitting.

### 3. Unchecked split_at in capability parsing

- **File:** `src/caps/packet.rs:62`
- **Code:**
  ```rust
  let (cap, input) = input.split_at(cap_header.length as usize);
  ```
- **Problem:** `cap_header.length` is a u8 from untrusted packet data. No
  validation that `cap_header.length <= input.len()`.
- **Trigger:** BGP OPEN with malformed capability: length field larger than
  capability data remaining.
- **Fix:** Check length before `split_at()`.

### 4. Arithmetic underflow on UPDATE packet length

- **File:** `src/update.rs:280`
- **Code:**
  ```rust
  let nlri_len = packet.header.length - BGP_HEADER_LEN - 2 - withdraw_len - 2 - attr_len;
  ```
- **Problem:** No validation that
  `packet.header.length >= BGP_HEADER_LEN + 2 + withdraw_len + 2 + attr_len`.
  Unsigned integer underflow produces a huge `nlri_len` value passed to
  `parse_bgp_nlri_ipv4()`.
- **Trigger:** Malformed BGP UPDATE where withdraw_len + attr_len exceeds
  available bytes.
- **Fix:** Use `saturating_sub()` or validate before subtraction.

### 5. Arithmetic underflow on NOTIFICATION packet length

- **File:** `src/notification.rs:407`
- **Code:**
  ```rust
  let len = packet.header.length - BGP_HEADER_LEN - 2;
  let (input, _data) = take(len as usize).parse(input)?;
  ```
- **Problem:** No check that `packet.header.length >= BGP_HEADER_LEN + 2`.
  Unsigned underflow results in a huge `len` value.
- **Trigger:** Malformed BGP NOTIFICATION with header.length < 21.
- **Fix:** Validate header length before subtraction.

## High (Panic on specific input values)

### 6. Unsafe unwrap on AttributeFlags

- **File:** `src/attrs/attr.rs:214`
- **Code:**
  ```rust
  let flags = AttributeFlags::from_bits(flags_byte).unwrap();
  ```
- **Problem:** `from_bits()` returns `None` if `flags_byte` has undefined bits
  set. The `unwrap()` panics on invalid flags.
- **Trigger:** BGP UPDATE with malformed attribute flags byte (e.g., reserved
  bits set).
- **Fix:** Use `from_bits_truncate()` or handle the `None` case.

### 7. Off-by-one in aggregator ASN range check

- **File:** `src/attrs/aggregator.rs:119-120`
- **Code:**
  ```rust
  let asn: u16 = if value.asn <= 65536 {
      value.asn.try_into().unwrap()
  } else {
      AS_TRANS
  };
  ```
- **Problem:** u16 max is 65535, but the condition allows 65536 through. The
  `try_into().unwrap()` panics for ASN 65536.
- **Trigger:** BGP UPDATE with aggregator ASN == 65536.
- **Fix:** Change condition to `value.asn <= 65535` or `value.asn <= u16::MAX as u32`.

### 8. Premature parsing before length validation in VPNv4 NLRI

- **File:** `src/attrs/nlri_vpnv4.rs:30-46`
- **Code:**
  ```rust
  let (input, mut plen) = be_u8(input)?;
  let psize = nlri_psize(plen);
  // ... parses label (3 bytes) and RD (8 bytes) ...
  if plen < 88 {
      return Err(...);
  }
  plen -= 88;
  ```
- **Problem:** Code parses MPLS label (3 bytes) and Route Distinguisher
  (8 bytes) before validating `plen >= 88`. If the input buffer is too short,
  `take(3)` or `RouteDistinguisher::parse_be()` may consume non-existent bytes.
- **Trigger:** VPNv4 NLRI with `plen < 88` and insufficient input data.
- **Fix:** Validate `plen >= 88` before parsing label and RD.

## Low

### 9. Unnecessary unwrap in peek function

- **File:** `src/parser.rs:53`
- **Code:**
  ```rust
  u16::from_be_bytes(len.try_into().unwrap()) as usize
  ```
- **Problem:** The `.get(16..18)` guard makes this safe, but `unwrap()` is poor
  practice in parser code.
- **Fix:** Replace with `u16::from_be_bytes([len[0], len[1]])`.
