# bgp-packet - Would-be Changes (Buffer Overrun / Underrun)

This file records the **would-be fixes** identified by the 2026-08-07 buffer overrun/underrun investigation of `crates/bgp-packet/src`. No code was changed; this is a documentation of the exact edits that would be made, and their impact, for the owner to decide.

Source audit baseline: `AUDIT.md` at `bbda8a44` (Security: no open panic/DoS; remaining items are validation leniency F8/F9 and emit-side latent F2).

## Scope

`crates/bgp-packet/src/parser.rs` + all other files under `crates/bgp-packet/src` (`packet.rs`, `open.rs`, `update.rs`, `notification.rs`, `route_refresh.rs`, `label.rs`, `caps/*`, `attrs/*`). Shell sandbox was down so verification was static (`search`/`read_file`) only.

## Summary

No classic memory overrun (`unsafe`, raw `split_at`, unchecked `&input[x..y]`) was found - every wire length is bounded with `packet_utils::safe_split_at` and `nom::take` returns `Incomplete` on truncation, not panic. Remaining gaps are logical framing: unvalidated `BgpHeader.length`, `saturating_sub`-masked underrun, and emit-side `len as u8/u16` wraps. All were already flagged as AUDIT F2/F8/F9 (latent/low).

---

## Would-be changes

### 1. `src/parser.rs:95` - `peek_bgp_length` returns unvalidated lengths (F9 latent)

**Current:**
```rust
pub fn peek_bgp_length(input: &[u8]) -> Option<usize> {
    if input.len() < BGP_HEADER_LEN.into() { return None; }
    let length = u16::from_be_bytes([input[16], input[17]]) as usize;
    (input.len() >= length).then_some(length)
}
```

**Would-be:**
```rust
pub fn peek_bgp_length(input: &[u8], opt: &ParseOption) -> Option<usize> // or peek_bgp_length_validated
{
    if input.len() < BGP_HEADER_LEN.into() { return None; }
    let length = u16::from_be_bytes([input[16], input[17]]) as usize;
    if length < BGP_HEADER_LEN as usize { return None; }
    if length > opt.max_message_len() { return None; } // 4096 or 65535
    (input.len() >= length).then_some(length)
}
```
**Impact:** Traps future caller that trusts `Some(0..18)` or `Some(>max)`. Current sole caller re-checks, so no live change. API break: adds `&ParseOption` param or introduces new `_validated` variant.

### 2. `src/parser.rs:103` - `BgpPacket::parse_packet` no header validation

**Current:** `peek(BgpHeader::parse_be)` then dispatch with no `marker == [0xff;16]`, no `length >=19`, no `input.len() >= header.length` check. `Keepalive` just `BgpHeader::parse_be`.

**Would-be:** After `peek`, validate:
```rust
if header.marker != [0xff; 16] { return Err(LengthValue); }
if header.length < BGP_HEADER_LEN { return Err(LengthValue); }
if header.length as usize > opt.map_or(BGP_PACKET_LEN, |o| o.max_message_len()) { return Err(LengthValue); }
// Ensure framed message is exactly header.length: caller must have sliced with safe_split_at(header.length)
```
Plus per-type:
- `Keepalive` => `ensure!(header.length == BGP_HEADER_LEN)`
- `RouteRefresh` => see #5
- `Notification/Update/Open` => after sub-parse ensure `remaining.is_empty()` against header.length.

**Impact:** Prevents mis-framing when called on raw TCP stream. Requires `opt` already threaded.

### 3. `src/notification.rs:453` - `saturating_sub` masks truncated NOTIFICATION Data

**Current:** `let len = header.length.saturating_sub(19).saturating_sub(2); take(len)`

**Would-be:**
```rust
let len = header.length.checked_sub(BGP_HEADER_LEN).ok_or(LengthValue)?
    .checked_sub(2).ok_or(LengthValue)?;
let (input, data) = take(len as usize).parse(input)?;
if header.length as usize != BGP_HEADER_LEN as usize + 2 + data.len() { return Err(LengthValue); }
```

**Impact:** Truncated NOTIFICATION now errors instead of `take(0)` silently succeeding. No overrun (take is bounded), but underrun surfaced.

### 4. `src/update.rs:624` - `saturating_sub` masks truncated UPDATE NLRI

**Current:** `nlri_len = header.length.saturating_sub(19).saturating_sub(2).saturating_sub(withdraw_len).saturating_sub(2).saturating_sub(attr_len)`

**Would-be:** Replace chain with `checked_sub` -> `Err(LengthValue)` on `None`. Also verify `header.length == 19+2+withdraw_len+2+attr_len+nlri_len` before `parse_bgp_nlri_ipv4`.

**Impact:** Short UPDATE now fails instead of parsing 0-length NLRI block.

### 5. `src/route_refresh.rs:35` - skips length / trailing-byte validation (F8 confirmed low)

**Current:** `pub fn parse_packet(input: &[u8]) -> IResult { Self::parse_be(input) }`

**Would-be:**
```rust
pub fn parse_packet(input: &[u8]) -> IResult {
    let (rest, pkt) = Self::parse_be(input)?;
    if pkt.header.length != ROUTE_REFRESH_TOTAL_LEN { return Err(LengthValue); }
    if !rest.is_empty() { /* caller sliced header.length, but if called on stream, reject padded body */ }
    // Also validate header.marker and typ==5
    Ok((rest, pkt))
}
```

**Impact:** Padded ROUTE_REFRESH now rejected per RFC 7313 §6.

### 6. Emit-side `len as u8 / len as u16` wraps - F2 latent (16+ sites)

**Files:** `src/attrs/mp_reach.rs:858(+7)`, `mp_unreach.rs:8 sites`, `nlri_bgpls.rs:184,316,494,675`, `bgpls_attr.rs:156`, `nlri_evpn.rs:1153-1377` (11 per-route `payload.len() as u8`), `nlri_mup.rs:679`, `prefix_sid.rs:406`, `srpolicy.rs:595-597`, `emitter.rs:24,28`, `tunnel_encap.rs:103,113`, `nlri_vpnv4.rs:200,204`, `update.rs:114,134,149,257,261,311` (pop_*).

**Current:** `buf.put_u8(len as u8)` / `buf.put_u16(len as u16)` on attribute/NLRI length.

**Would-be:** Make `AttrEmitter`/`NlriEmitter` fallible:
```rust
trait AttrEmitter { fn emit(&self, buf: &mut BytesMut) -> Result<(), UpdateEmitError>; }
fn fit_len(field: &'static str, len: usize) -> Result<u16/u8, UpdateEmitError> { u16::try_from(len).map_err(|_| TooLong{field,len})? }
```
Every emitter uses `fit_len` / `fit_len_u8`, and `UpdatePacket::try_emit` already does for top-level header (`a8b2d70a`). Variable bodies (MUP Unknown, EVPN LeafAd `route_key`, tunnel_encap TLV <128) already bounded ≤255 on parse path; local construction that exceeds the field is now `Err(TooLong)` instead of wrapping.

**Impact:** Large attribute body no longer wraps length octet and desyncs peer framing. Cascades through every attribute emitter (~16 trailer copies collapse as AUDIT notes).

### 7. No new direct-index `input[0]/[1]` panic, but document guard

`src/attrs/nlri_evpn.rs:1065` and `src/attrs/srpolicy.rs:431` index `input[1]/[2]` only after `if input.len()<2/3 { return Err }` - already safe. No change, but keep guard if refactoring.

---

## Invariants to preserve (from AUDIT.md)

1. Bound every length-prefixed slice with `safe_split_at`, never raw `split_at`/direct indexing on wire input.
2. After parsing inside bounded slice, reject `!remaining.is_empty()` with `LengthValue`.
3. Validate `plen` against family max before `nlri_psize`, check buffer before fixed-width copy.
4. Fixed-width repeating attributes: reject empty or non-multiple-of-size payloads.
5. Emitters: derive `len()` and emitted bytes from one clamp/count helper, or make fallible.

## Decision

Owner to triage: #1/#2/#5 are optional tightening (future-proofing), #3/#4 surface silent truncation, #6 is the F2 refactor that cascades. None are live DoS; all edits would be semver-compatible except #1/#6 API changes.
