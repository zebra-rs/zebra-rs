# Code Review — `crates/ospf-packet/`

**Scope:** the whole `ospf-packet` crate (OSPFv2/v3 packet parse & emit for zebra-rs)
**Effort:** extra-high recall (10 finder angles × 8 candidates + verification pass + gap sweep)
**Date:** 2026-07-17
**Updated:** 2026-07-18 — findings 1–7 (all three DoS bugs + all four interop
wire-format bugs) fixed and merged. See **Status** and **Next fix candidates**
below. Detail-section line numbers are as of the original 2026-07-17 review; the
summary table's `File:line` for open items (8–15) is refreshed to the current tree.

Every finding below was verified by reading the actual code. Findings are ranked
most-severe first.

---

## Summary table

| # | Severity | File:line | Bug | Status |
|---|----------|-----------|-----|--------|
| 1 | **DoS (panic)** | `parser.rs:1613` | Extended-Prefix TLV writes past `[u8;4]` when `prefix_len > 32` | ✅ #1959 |
| 2 | **DoS (panic)** | `v3.rs:3418` | SRv6 Locator TLV copies up to 32 bytes into `[u8;16]` | ✅ #1959 |
| 3 | **DoS (alloc)** | `parser.rs:401` (+`v3.rs:2987/1517/1077`) | `Vec::with_capacity` from unvalidated wire count | ✅ #1959 |
| 4 | **Interop** | `v3.rs:498` | OSPFv3 Options AT-bit at bit 13, not RFC 7166 bit 10 | ✅ #1963 |
| 5 | **Interop** | `parser.rs:1691` | `PrefixSidFlags` every flag one bit too high | ✅ #1966 |
| 6 | **Interop** | `v3.rs:1708` (+`1769`) | OSPFv3 Adj-SID Weight is 16-bit at the wrong offset | ✅ #1970 |
| 7 | **Interop** | `v3.rs:3149` (+`3210`) | SRv6 End.X SID header is 8 bytes; RFC 9513 is 6 | ✅ #1974 |
| 8 | **Round-trip** | `parser.rs:1214` | Unknown RouterInfo TLV reads type/len from value bytes | ✅ #1982 |
| 9 | **Security** | `zebra-rs/.../network_v6.rs:124` | v3 checksum skipped when any trailing bytes present | ✅ #1979 |
| 10 | **Correctness** | `parser.rs:557` | `verify_checksum` re-emits typed form, ignores `raw` | ⬜ open |
| 11 | **Robustness** | `parser.rs:693` | `parse_lsa_with_length` swallows all errors into `Unknown` | ⬜ open |
| 12 | **Correctness** | `parser.rs:422` (+`816`) | v2 emit writes stored `num_adv`/`num_links`, not derived | ⬜ open |
| 13 | **Correctness** | `parser.rs:82` (+`227`) | Unknown v2 payload emit drops body; `typ()` → Hello | ⬜ open |
| 14 | **Cleanup (reuse)** | `parser.rs:618` | Fletcher checksum + FAD/SID codecs duplicated | ⬜ open |
| 15 | **Cleanup (dead code)** | `parser.rs:1197` (+`1077`, `v3.rs`) | Dead `pub` items add confusing API surface | ⬜ open |

---

## Status (2026-07-18)

All seven top findings — the three remote-DoS parse bugs and all four silent
interop wire-format bugs — plus the security finding #9 and the round-trip
finding #8 are fixed and merged to `main`. The review document itself landed in
#1955.

| PR | Findings | Summary |
|----|----------|---------|
| [#1959](https://github.com/zebra-rs/zebra-rs/pull/1959) | 1, 2, 3 | Reject oversized `prefix_len`/`locator_length`; `packet_utils::bounded_capacity` caps wire-count pre-allocation (4 sites) |
| [#1963](https://github.com/zebra-rs/zebra-rs/pull/1963) | 4 | AT Options bit moved to RFC 7166 bit 10 (`0x400`) |
| [#1966](https://github.com/zebra-rs/zebra-rs/pull/1966) | 5 | `PrefixSidFlags` shifted to RFC 8665/8666 positions; **+ BDD `ospfv3_prefix_sid_flags`** |
| [#1970](https://github.com/zebra-rs/zebra-rs/pull/1970) | 6 | Adj-SID / LAN-Adj-SID `weight` → `u8` at offset 1 (RFC 8666 §6.1/§6.2) |
| [#1974](https://github.com/zebra-rs/zebra-rs/pull/1974) | 7 | End.X / LAN-End.X SID head → 6 bytes (RFC 9513 §9.1/§9.2) |
| [#1979](https://github.com/zebra-rs/zebra-rs/pull/1979) | 9 | v3 receive checksum verified over `input[..pkt_len]` unconditionally, closing the trailing-bytes bypass; **validated by `ospfv3_auth` BDD** |
| [#1982](https://github.com/zebra-rs/zebra-rs/pull/1982) | 8 (part of 15) | Unknown Router-Information TLV built from the header, not the value bytes; dead `RouterInfoTlvUnknown::parse_tlv` removed |

Each fix carries a regression test: byte-offset unit tests where a `show`-based
check could not discriminate the bug, plus live BDD features for the Prefix-SID
flags (#1966) and the auth-trailer receive path (#1979). Findings 6, 7 have no
BDD because the daemon originates those fields as zero, so a zebra-to-zebra
`show` renders identically under either layout — the unit tests are the
meaningful lock.

---

## Next fix candidates (prioritized)

The remaining findings are all lower-severity than the merged set (no DoS, no
silent interop break in a shipped datapath). Suggested order:

> Findings 8 and 9 — the previous Tier-1 items — are fixed: #9 (v3 checksum-skip
> bypass) in [#1979](https://github.com/zebra-rs/zebra-rs/pull/1979), #8 (Unknown
> RouterInfo TLV round-trip) in [#1982](https://github.com/zebra-rs/zebra-rs/pull/1982).

**Tier 1 — correctness / robustness, moderate effort**
1. **Finding 12 — derive `num_adv` / `num_links` at emit.** Mirror the v3 codec
   (`Ospfv3LsUpdate::emit`), then delete the manual sync lines in the daemon
   (`inst.rs:1983`, `inst.rs:5404/5502/5571`). Touches daemon call sites.
2. **Finding 11 — `parse_lsa_with_length` should not swallow parse failures.**
   Distinguish "unknown LS type" (→ `Unknown`, keep tolerant flooding) from
   "known type, body failed to parse" (→ propagate `Err`). Needs care to avoid
   regressing the intentional unmodeled-sub-TLV tolerance.
3. **Finding 10 — `verify_checksum` should use `self.raw`.** Low effort; latent
   today (only the crate's tests call it), so low urgency until it is wired into
   an ingress path. Pairs with the non-bijective `From<u8>` note below.

**Tier 2 — low-severity / cleanup**
4. **Finding 13 — Unknown v2 payload emit drops body / `typ()` → Hello.** Latent
   (daemon never re-emits unknown-type packets); fix the public-API trap when
   convenient.
5. **Finding 15 (remainder) — delete dead `pub` items** (`is_known`,
   `Ospfv3ExtTlv::wire_len`; `RouterInfoTlvUnknown::parse_tlv` was already removed
   with finding 8). Trivial deletions.
6. **Finding 14 — hoist duplicated codecs into `packet-utils`** (Fletcher
   checksum shared with `isis-packet`; FAD and SID/Label dispatch shared v2/v3).
   Larger refactor; best done the next time those codecs are touched.

**Additional notes (below the top 15)** — opportunistic:
- `parser.rs` / `v3.rs` emit: stamp packet length via `try_into`/`checked` so a
  >64 KB serialization fails loudly instead of silently wrapping the `u16`.
- Non-bijective `From<u8>` for link types (unknown → `Stub`/`PointToPoint`) —
  fold into finding 10's fix, since it contributes to the `verify_checksum`
  false-reject.
- Efficiency: `raw_body` eager copy on every received packet; `Ospfv3Lsa::update`
  serializes the body twice. Per-packet hot paths.
- `Ospfv3IntraAreaPrefixTlv` (RFC 8362 E-Intra-Area-Prefix TLV) — verify the
  16-bit-metric + referenced-LSA-triple layout against RFC 8362 §3.9; internal
  round-trips pass (zebra-to-zebra) but it was never interop-validated.

---

## Correctness / security findings

### 1. Extended-Prefix TLV panics on `prefix_len > 32` — remote DoS
> ✅ **Fixed in [#1959](https://github.com/zebra-rs/zebra-rs/pull/1959).**

**`crates/ospf-packet/src/parser.rs:1613`**

`ExtPrefixTlv::parse_tlv` copies prefix octets into a fixed `[u8; 4]` indexed by a
count derived from the wire prefix-length:

```rust
let prefix_bytes = (prefix_len as usize).div_ceil(8);   // up to 32 for prefix_len 255
...
let mut addr_bytes = [0u8; 4];
for (i, b) in prefix_data.iter().take(prefix_bytes).enumerate() {
    addr_bytes[i] = *b;                                  // addr_bytes[4] → panic
}
```

A received OSPFv2 LS Update carrying an Extended-Prefix Opaque LSA whose TLV
`prefix_len` byte is `33..=255` makes `prefix_bytes = 5..=32`, so the loop writes
`addr_bytes[4]` → index-out-of-bounds panic. The `Err`-catching wrapper in
`parse_lsa_with_length` does **not** catch panics, so one packet crashes the
parser.

**Fix:** clamp the copy to 4 (`.take(prefix_bytes.min(4))`) or reject
`prefix_len > 32` before building the address.

---

### 2. SRv6 Locator TLV panics on `locator_length > 128` — remote DoS
> ✅ **Fixed in [#1959](https://github.com/zebra-rs/zebra-rs/pull/1959).**

**`crates/ospf-packet/src/v3.rs:3418`** (emit twin at `v3.rs:3403`)

```rust
let wire = ospfv3_prefix_wire_len(locator_length);  // ceil(len/32)*4 → up to 32
let (mut input, raw) = take(wire)(input)?;
let mut octets = [0u8; 16];
octets[..wire].copy_from_slice(raw);                // wire=20..32 on a 16-byte array → panic
```

`locator_length` is an unvalidated `be_u8`. A Locator LSA with `locator_length`
in `129..=255` panics on the slice. The emit path (`&self.locator.octets()[..wire]`)
has the same defect for any constructed value.

**Fix:** bound `wire` to 16 (or reject `locator_length > 128`).

---

### 3. Unbounded `Vec::with_capacity` from wire count — remote DoS
> ✅ **Fixed in [#1959](https://github.com/zebra-rs/zebra-rs/pull/1959)** — via `packet_utils::bounded_capacity`.

**`crates/ospf-packet/src/parser.rs:401`**, plus **`v3.rs:2987`**, **`v3.rs:1517`** (u32), **`v3.rs:1077`** (u16)

```rust
// OspfLsUpdate { num_adv: u32, ... }
let mut out = Vec::with_capacity(n);   // n = num_adv, straight off the wire
```

A minimal LS Update (header + `# advertisements` word only) with
`num_adv = 0xFFFFFFFF` forces `Vec::with_capacity(~4.29e9 × sizeof(OspfLsa))` —
a hundreds-of-GB reservation — before the parse loop runs. Allocation failure
aborts the process. Same pattern in the OSPFv3 LS Update, Link-LSA, and
Intra-Area-Prefix-LSA parsers.

**Fix:** clamp capacity to `n.min(input.len() / MIN_LSA_SIZE)`, or start from
`Vec::new()` and let it grow.

---

### 4. OSPFv3 Options AT-bit at bit 13 instead of RFC 7166 bit 10 — interop
> ✅ **Fixed in [#1963](https://github.com/zebra-rs/zebra-rs/pull/1963).**

**`crates/ospf-packet/src/v3.rs:498`**

```rust
pub v6, e, mc, n, r, dc: bool,   // bits 0..5
#[bits(7)] pub _reserved_6_12: u32,
pub at: bool,                    // bit 13  ← should be bit 10
```

RFC 7166 / IANA (and FRR `OSPF6_OPT_AT = 1<<10 = 0x400`) put the
Authentication-Trailer bit at bit 10. The reserved gap is 3 bits too wide.
`set_at(true)` writes `0x2000`; a compliant peer's `0x400` lands in
`_reserved_6_12` so `options.at()` is always false. RFC 7166 AT negotiation is
silently broken in both directions against any interoperable router.

**Fix:** `#[bits(4)] _reserved_6_9` then `at` at bit 10 (widen the trailing
reserved accordingly).

---

### 5. `PrefixSidFlags` every flag one bit too high — interop
> ✅ **Fixed in [#1966](https://github.com/zebra-rs/zebra-rs/pull/1966)** — with BDD `ospfv3_prefix_sid_flags`.

**`crates/ospf-packet/src/parser.rs:1691`**

```rust
#[bits(3)] pub resvd: u8,   // bits 0..2
pub l_flag, v_flag, e_flag, m_flag, np_flag: bool,   // bits 3..7 → NP=0x80
```

RFC 8665 §6 / RFC 8666 (and FRR `EXT_SUBTLV_PREFIX_SID_*FLG`) define
`NP=0x40, M=0x20, E=0x10, V=0x08, L=0x04` with the MSB reserved. Every flag is
shifted one bit too high. A peer's `NP` (0x40) reads as `M`; emitting `NP` sets
the reserved 0x80; `V`/`L` are likewise misread → wrong value-vs-index and
local-vs-global handling → wrong MPLS label programming across implementations.

**Fix:** put the 3 reserved bits at the top (`np` at bit 6, …, `l` at bit 2,
`#[bits(2)] resvd` at bits 0-1) — i.e. mirror the RFC bit numbering.

---

### 6. OSPFv3 Adj-SID / LAN-Adj-SID Weight is 16-bit at the wrong offset — interop
> ✅ **Fixed in [#1970](https://github.com/zebra-rs/zebra-rs/pull/1970).**

**`crates/ospf-packet/src/v3.rs:1708`** and **`v3.rs:1769`**

```rust
buf.put_u8(self.flags.into());
buf.put_u8(0);          // "reserved"
buf.put_u16(self.weight);   // weight as u16 at offsets 2-3
```

RFC 8666 §6.1/§6.2 defines `Flags(8) | Weight(8) | Reserved(16)` — Weight is a
single octet at offset 1 (SR Weight is 1 octet in every SR RFC). A conforming
peer reads Weight from octet 1 (always 0 here) and the real weight (octets 2-3)
as Reserved, so a non-zero-weight Adj-SID decodes as weight 0 — weighted-ECMP
over adjacency SIDs silently breaks. Emit/parse mirror the same wrong offsets and
the round-trip test uses `weight=0`, so unit tests never catch it.

**Fix:** `weight: u8`, emit `flags(1) | weight(1) | reserved(2)`.

---

### 7. SRv6 End.X / LAN-End.X SID header is 8 bytes; RFC 9513 is 6 — interop
> ✅ **Fixed in [#1974](https://github.com/zebra-rs/zebra-rs/pull/1974).**

**`crates/ospf-packet/src/v3.rs:3149`** and **`v3.rs:3210`**

```rust
buf.put_u16(self.behavior);
buf.put_u8(self.flags);
buf.put_u8(0);          // reserved1  ← extra octet not in the RFC
buf.put_u8(self.algo);
buf.put_u8(self.weight);
buf.put_u16(0);         // reserved2  ← RFC has a single reserved octet here
buf.put_slice(&self.sid.octets());   // value_len 24; RFC total is 22
```

RFC 9513 §9.1/§9.2: `Behavior(2) | Flags(1) | Algorithm(1) | Weight(1) |
Reserved(1) | SID(16)`. The code inserts a reserved octet before Algorithm and
uses a 2-byte reserved after Weight, shifting Algorithm, Weight, and the 128-bit
SID (plus any nested SID-Structure sub-TLV) relative to any conforming peer →
the installed SRv6 forwarding SID is garbage. Zebra-to-zebra round-trips pass
because emit/parse agree and tests use `weight=0`.

**Fix:** remove `reserved1`; make the post-Weight reserved a single octet.

---

### 8. Unknown RouterInfo TLV reads type/len from the value bytes — round-trip corruption
> ✅ **Fixed in [#1982](https://github.com/zebra-rs/zebra-rs/pull/1982)** — build the Unknown variant from the header; dead `parse_tlv` deleted.

**`crates/ospf-packet/src/parser.rs:1208`**

```rust
let (input, tl) = TlvTypeLen::parse_be(input)?;      // 4-byte header consumed
let (input, tlv) = packet_utils::safe_split_at(input, len)?;   // tlv = value only
let (_, val) = Self::parse_be(tlv, typ)?;            // Unknown arm re-reads typ:u16/len:u16 from `tlv`
```

For an unrecognized TLV the derived `RouterInfoTlvUnknown` parse reads
`typ`/`len` from the first 4 **value** octets, not the header. A TLV
(type 100, len 8, value `AA BB CC DD EE FF 00 11`) parses to `typ=0xAABB,
len=0xCCDD, values=[EE FF 00 11]`; re-emit writes a different type, length and
payload, desynchronizing the stream. An unknown TLV with `<4` value bytes errors
and `many0_complete` silently drops all remaining RI TLVs. The correct
`RouterInfoTlvUnknown::parse_tlv` helper exists but is dead code (finding 15).

**Fix:** wire the manual `parse_tlv` (carry `tl.typ`/`tl.len`, values = full
value slice) into the `Unknown` arm.

---

### 9. OSPFv3 checksum verification skipped when any trailing bytes present — integrity bypass
> ✅ **Fixed in [#1979](https://github.com/zebra-rs/zebra-rs/pull/1979)** — verify over `input[..pkt_len]` unconditionally; validated by `ospfv3_auth` BDD.

**`zebra-rs/src/ospf/network_v6.rs:124`** *(consumer-side, driven by the crate's positional auth-trailer design)*

```rust
let has_trailer = input.len() > pkt_len;
if !has_trailer && !ospfv3_verify_checksum(&src, &dst, input) {
    return Err(ErrorKind::InvalidData.into());
}
```

`has_trailer` is a heuristic on trailing bytes existing, not on auth being
configured. On an unauthenticated interface, appending ≥1 garbage byte makes
`has_trailer` true, so a packet with a wrong pseudo-header checksum is never
validated; if `parse_v3` tolerates the trailing bytes the corrupt packet is
accepted. *(Confirm `parse_v3`'s acceptance to fully close this.)*

**Fix:** gate the skip on authentication being configured for the interface, not
on the mere presence of trailing bytes; the crate could expose an explicit
"trailer present + valid" signal instead of a length heuristic.

---

### 10. `OspfLsa::verify_checksum` re-emits the typed form and ignores `raw`
**`crates/ospf-packet/src/parser.rs:551`**

```rust
let mut buf = BytesMut::with_capacity(self.h.length as usize);
self.h.emit(&mut buf);
self.emit_lsp(&mut buf);            // typed re-emit, NOT self.raw
...
let computed = lsa_checksum_calc(&buf[2..], 14);
```

`parse_lsas_with_raw`'s own comment says the typed parser may reorder/drop
sub-TLVs — which is why `raw` is cached for re-flooding. But `verify_checksum`
recomputes over the typed re-emit, so any LSA whose typed emit isn't byte-exact
(unknown RI TLV per finding 8, unmodeled sub-TLVs, a link type remapped by the
non-bijective `From<u8>` at `parser.rs:754` / `v3.rs:701`) fails checksum
validation despite being valid. **Currently only called from the crate's tests**,
so it's latent — but it's a live false-reject the moment it's used at ingress.

**Fix:** when `self.raw` is present, run `lsa_checksum_calc` over the cached wire
bytes; fall back to the typed re-emit only when `raw` is `None`.

---

### 11. `parse_lsa_with_length` swallows all parse errors into `Unknown`
**`crates/ospf-packet/src/parser.rs:704`**

```rust
match OspfLsp::parse_be(payload_input, selector) {
    Ok((_, parsed)) => Ok((remaining, parsed)),
    Err(_) => Ok((remaining, OspfLsp::Unknown(UnknownLsa { data: payload_input.to_vec() }))),
}
```

A truncated/corrupt **known-type** LSA decodes silently as `Unknown` and is
re-flooded verbatim from the raw cache instead of being rejected at ingress, so
on-wire corruption or a peer bug propagates through the area. The catch-all is
useful for tolerating unmodeled sub-TLVs but shouldn't mask a body that fails to
parse at all.

**Fix:** distinguish "unknown LS type" (→ `Unknown`) from "known type, body
failed to parse" (→ propagate `Err`).

---

### 12. v2 emit writes stored `num_adv` / `num_links` instead of deriving them
**`crates/ospf-packet/src/parser.rs:416`** (and `RouterLsa::emit`, `parser.rs:810`)

`OspfLsUpdate::emit` writes `self.num_adv` verbatim; `RouterLsa::emit` writes
`self.num_links`. The v3 codec derives these from `lsas.len()` at emit time
(`Ospfv3LsUpdate::emit`). The invariant is enforced ad-hoc at every v2 caller
(`inst.rs:1983`, `inst.rs:5404/5502/5571`). Any originate/mutate path that
appends but forgets to re-sync the counter emits a header count disagreeing with
the payload → peer drops the update or the adjacency wedges — a class of bug the
v3 side structurally cannot have.

**Fix:** derive the count from the vector length at emit (as v3 does) and delete
the manual sync lines.

---

### 13. Unknown v2 payload emit drops the body; `typ()` maps Unknown → Hello
**`crates/ospf-packet/src/parser.rs:82`** (and `parser.rs:227`)

`Ospfv2Packet::emit`'s `_ => {}` arm never writes an `Unknown` payload's bytes, so
re-emit produces a header-only packet with a truncated length/checksum;
`Ospfv2Payload::typ()` returns `OspfType::Hello` for `Unknown(_)` instead of the
stored type. Latent (the daemon doesn't re-emit received unknown-type packets),
but a silent data-loss trap in the public API.

**Fix:** emit the captured `Unknown` payload bytes and return the stored type
from `typ()`.

---

## Cleanup findings

### 14. Fletcher checksum + FAD/SID codecs duplicated
**`crates/ospf-packet/src/parser.rs:612`**

- `lsa_checksum_calc` re-implements the RFC 1008 Fletcher-with-offset math that
  `isis-packet` already has in `crates/isis-packet/src/checksum.rs`.
- The FAD constraint sub-TLV codec is copy-pasted between OSPFv2 (`parser.rs`
  ~1381) and OSPFv3 (`v3.rs:2259`, whose comment says "Mirrors the OSPFv2
  FAD/ASLA codec").
- The SID Label-vs-Index length dispatch (`match len { 3 => Label, 4 => Index }`)
  is re-inlined at ~9 sites though `parse_ospf_sid_label` (`parser.rs:1140`)
  already encapsulates it; nine `value_len` bodies re-inline `match sid { Label
  => 3, Index => 4 }` though `packet_utils::SidLabelTlv::len()` returns exactly
  that.

A fix or hardening applied to one copy silently misses the others, letting v2/v3
(or ospf/isis) drift. Move the shared payload codecs into `packet-utils` (where
`ExtAdminGroup`/`SidLabelTlv` already live for this reason) and call one impl.

---

### 15. Dead `pub` items add confusing API surface
**`crates/ospf-packet/src/parser.rs:1190`** (and `parser.rs:1070`, `v3.rs:2577`)

- `RouterInfoTlvUnknown::parse_tlv` — never wired in (it's the correct fix for
  finding 8).
- `RouterInfoTlvType::is_known` — no callers; its answer is also misleading
  since more TLV types are actually decoded than it reports.
- `Ospfv3ExtTlv::wire_len` — kept alive only by a stale `#[allow(dead_code)]`
  whose "consumed by PR-D2+" note is obsolete; no callers.

`grep` confirms no uses in `crates/` or `zebra-rs/`. Delete them (wiring the
real `parse_tlv` into finding 8's fix first).

---

## Additional notes (surfaced but below the top 15)

- **`parser.rs:88` / `v3.rs:324`** — packet length stamped via `buf.len() as u16`
  truncates for a serialized packet > 64 KB. Latent: OSPF packet length is a
  16-bit field and the daemon keeps LSUs under MTU, but a `checked`/`try_into`
  would fail loudly instead of silently wrapping.
- **`parser.rs:754` / `v3.rs:701`** — `From<u8>` for link types maps every
  unknown value to `Stub` / `PointToPoint` (non-bijective). Harmless for
  re-flood (uses `raw`) but contributes to the `verify_checksum` false-reject in
  finding 10.
- **Efficiency** — `raw_body` is eagerly copied for every received packet even
  when no cryptographic auth is configured (`parser.rs:2823`, `v3.rs:133`);
  `Ospfv3Lsa::update` serializes the body twice (`v3.rs:2928`). Per-packet hot
  paths; prefer zero-copy `Bytes::slice` and single-pass emit.
- **`v3.rs:2009`** — `Ospfv3IntraAreaPrefixTlv` (RFC 8362 E-Intra-Area-Prefix
  TLV) uses a 16-bit metric and an embedded referenced-LSA triple. Worth
  double-checking the field layout against RFC 8362 §3.9; internal round-trips
  pass so zebra-to-zebra works, but it was not interop-validated (FRR does not
  implement the OSPFv3 Extended-LSA / SRv6 SR sub-TLVs).
