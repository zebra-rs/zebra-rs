# bgp-packet Code Review Findings

**Review date:** 2026-07-16
**Scope:** whole-crate review of `crates/bgp-packet/` (committed tree; no pending diff)
**Effort:** xhigh recall — 10 finder angles fanned across every file, candidates
adversarially verified, ranked most-severe first.

## Summary

The crate's **parse paths are well hardened against memory-safety bugs**. Every
angle that hunted for panics / over-reads on malicious input (EVPN, MUP,
MP_REACH, flowspec, prefix-SID, BGP-LS, VPN NLRI) confirmed the same thing:
bounded `packet_utils::safe_split_at` / nom `take` throughout, fixed-array copies
guarded by exact-width checks, and `saturating_sub` on the underflow paths. The
claims in `SECURITY_AUDIT.md` hold up.

The findings below are therefore **functional / interop correctness** issues, not
crashes. Two systemic themes recur:

1. **Length / consumption asymmetry with parsing.** `many0_complete` plus a
   caller that discards the leftover slice means a malformed NLRI (or a
   non-multiple-of-width community list) silently truncates the rest of the list
   instead of RFC 7606 treat-as-withdraw.
2. **Emit-side `as u8` / `as u16` length casts** with no split/clamp (aspath,
   update, MP_REACH, BGP-LS, flowspec). Mostly latent behind message-size caps —
   but the AS_PATH one is live.

Verdicts: **CONFIRMED** = inputs/state and wrong output identified against the
source; **PLAUSIBLE** = mechanism is real, trigger depends on config/peer/timing.

---

## Findings (ranked)

### 1. Unknown capability with a 0/1-octet body breaks session establishment — CONFIRMED — ✅ FIXED
- **File:** `src/caps/unknown.rs:10` (with `src/caps/packet.rs:63-71`)
- **Category:** correctness
- **Status:** Fixed on branch `fix-bgp-cap-unknown-header`. `CapUnknown` no longer
  parses a `CapabilityHeader` from the value slice — it now holds `#[nom(Ignore)]
  code: u8` + `data: Vec<u8>`, and `parse_cap` stamps the real code (already in
  `cap_header`) into the Unknown variant. Regression tests in `caps/packet.rs`
  cover the RFC 9234 Role capability (code 9, len 1), a zero-length unknown
  capability, and a still-typed known capability.
- **Bug:** `CapUnknown` derives `NomBE` with a leading `header: CapabilityHeader`
  field, but `parse_cap` has already consumed the 2-byte cap header and
  `safe_split_at`-sliced the body to exactly `length` bytes before dispatching to
  the variant. The Unknown arm then re-parses a 2-octet header that isn't there.
- **Failure scenario:** A peer includes the RFC 9234 BGP Role capability (code 9,
  length 1 — now common on Cisco/Juniper/FRR) in its OPEN. The 1-byte body can't
  satisfy `CapabilityHeader::parse_be` (needs 2 bytes) → `parse_cap` →
  `parse_caps` → `OpenPacket::parse_packet` all fail → zebra-rs rejects the OPEN
  and the session never establishes. RFC 5492 requires *ignoring* unknown
  capabilities. Every unknown capability with body < 2 octets triggers it; longer
  ones silently mis-store header/data.

### 2. Type-2 (4-octet-AS) Route Distinguisher fails to parse — CONFIRMED
- **File:** `src/attrs/rd.rs:8`
- **Category:** correctness
- **Bug:** `RouteDistinguisherType` models only `ASN = 0` and `IP = 1` with no
  catch-all variant, so the derived `NomBE` parser errors on any other RD type.
- **Failure scenario:** A peer advertises a VPNv4/VPNv6/EVPN/MUP route whose RD is
  type 2 (4-byte AS : 2-byte number, RFC 4364 — standard whenever the AS is
  4-byte). `RouteDistinguisher::parse_be` reads `typ=2`, finds no matching enum
  variant → nom error → the enclosing `Vpnv4Nlri`/`Vpnv6Nlri` parse fails →
  `many0_complete` silently drops that route. Type-2-RD VPN routes are never
  installed.

### 3. AS_SEQ segment count truncated by `as u8` — CONFIRMED
- **File:** `src/attrs/aspath.rs:126` (with `prepend_mut` at 447-462,
  `consolidate` at 579)
- **Category:** correctness
- **Bug:** `As4Segment::emit` writes the ASN count as `self.asn.len() as u8`, and
  `prepend_mut`/`consolidate` merge AS_SEQ segments with **no 255-ASN split**, so
  a segment holding > 255 ASNs emits a count byte that wraps and no longer matches
  the ASNs written.
- **Failure scenario:** A route arrives with a single AS_SEQ segment of the max
  255 AS4 numbers; on eBGP re-advertisement `prepend_mut` concatenates the local
  AS into that segment → 256 ASNs in one segment → `emit` writes `count = 256 as
  u8 = 0` followed by 256 u32 ASNs. The attribute length is correct, but a
  receiving peer reads a 0-length AS_SEQ then reparses the 256 ASNs as bogus
  segment headers → malformed AS_PATH → NOTIFICATION / session reset.

### 4. RTC parser rejects the `plen=0` default membership it emits — CONFIRMED
- **File:** `src/attrs/nlri_rtcv4.rs:24` (and `src/attrs/nlri_rtcv6.rs:29`)
- **Category:** correctness
- **Bug:** `Rtcv4::parse_nlri` rejects any `plen != 96`, including the RFC 4684
  default membership `plen=0` that `Rtcv4Reach::emit` itself produces (line 69).
- **Failure scenario:** `send_rtcv4_membership` / `send_rtcv6_membership` emit the
  zero-length default "all Route Targets" NLRI whenever the local import-RT set is
  empty (route.rs comment: *"Empty membership emits the zero-length default
  NLRI"*). A peer running zebra-rs receives `plen=0`, `parse_nlri` returns
  `Err(LengthValue)`, `many0_complete` stops with zero memberships → the peer
  treats us as wanting no Route Targets and never advertises VPN routes. Our own
  encoder produces packets our own parser rejects; partial-length (1..95) RTC
  prefixes are rejected too.

### 5. Non-AS4 peer's AS_PATH silently discarded — CONFIRMED
- **File:** `src/attrs/attr.rs:410`
- **Category:** correctness
- **Bug:** The `Attr::As2Path(_v) => { // TODO }` arm drops a parsed 2-octet
  AS_PATH, leaving `bgp_attr.aspath = None`.
- **Failure scenario:** A legacy peer that did not negotiate the AS4 capability
  sends a normal UPDATE; `parse_attr_value` runs with `as4=false`, so the AS_PATH
  is parsed as `As2Path` and then dropped. The route is installed with **no
  AS_PATH** (loop detection and AS-path-length best-path comparison broken) and is
  re-advertised without one, instead of being converted to 4-byte form or rejected
  as a missing well-known-mandatory attribute.

### 6. IPv6 extended community local-admin emitted native-endian — CONFIRMED
- **File:** `src/attrs/ext_ipv6_com.rs:68`
- **Category:** correctness
- **Bug:** `ExtIpv6CommunityValue::new` writes the 2-octet local-admin value with
  `to_ne_bytes()` (native endian) instead of `to_be_bytes()`; every other field in
  the file uses big-endian.
- **Failure scenario:** On x86_64/aarch64, `ExtIpv6Community::from_str("rt
  2001:db8::1:100")` → `new(addr, 0x0064)` stores `val[16..18] = [0x64, 0x00]`;
  `encode()` emits the swapped local-admin, so a remote peer decodes the RT/SoO
  value as `0x6400` (25600) instead of 100 → IPv6 route-target import/export
  matching fails. `Display` (lines 48-56) also reads an 8-octet-EC layout
  inconsistent with the 20-octet layout `new()` writes, so the value renders as
  garbage.

### 7. Flow-spec op-list overruns into the next component — PLAUSIBLE
- **File:** `src/attrs/nlri_flowspec.rs:168`
- **Category:** correctness
- **Bug:** `parse_op_list` is given the entire remaining NLRI value with no
  per-component length delimiter, relying solely on the end-of-list bit. A
  component whose op-list omits that bit consumes the following components' bytes.
  The doc comment claiming it "can't run into the next component" is false.
- **Failure scenario:** A crafted NLRI encodes a type-3 (IP-protocol) op with the
  end-of-list bit cleared followed by a type-4 (port) component. `parse_op_list`
  reads the next component's type/op bytes as further `{op,value}` terms → merges
  the two components or fails the whole NLRI → the installed flow-spec filter
  matches different traffic than intended (potential filter bypass). Bounded by
  the NLRI length so no over-read.

### 8. RTC withdraw emitter omits prefix-length and origin-AS — CONFIRMED (latent)
- **File:** `src/attrs/nlri_rtcv4.rs:116` (and `src/attrs/nlri_rtcv6.rs:121`)
- **Category:** correctness
- **Bug:** `Rtcv4Unreach::emit` writes only the 8-byte Route Target per withdraw,
  omitting the `plen(96)` and 4-byte origin-AS that `Rtcv4::parse_nlri` requires;
  the comment even mislabels the RT as "RD".
- **Failure scenario:** If a non-empty `Rtcv4Unreach` is emitted, the receiver's
  `parse_nlri` reads `plen` from the RT's first byte (typically `0x00`) `!= 96` →
  error → the withdrawal is dropped and stale VPN routes persist. **Currently
  latent:** `mp_unreach.rs` only builds `Rtcv4Unreach`/`Rtcv6Unreach` with an empty
  `withdraw` vec (the `Rtcv4Eor`/`Rtcv6Eor` End-of-RIB cases), so the malformed
  loop does not execute yet — but it is wrong the moment a real RTC withdraw is
  wired.

### 9. SR-MPLS Binding SID flags dropped on re-emit — PLAUSIBLE
- **File:** `src/attrs/srpolicy.rs:267` (emit at 478)
- **Category:** correctness
- **Bug:** `parse_binding_sid` keeps only the 20-bit label from an SR-MPLS Binding
  SID and discards the flag octet (S/I flags); `emit_binding_sid` re-emits
  `Flags=0`.
- **Failure scenario:** A router receives a Binding SID sub-TLV (type 13) with the
  S or I flag set and re-advertises it (route reflector or eBGP); the re-encoded
  sub-TLV zeroes the flag octet, changing the binding-SID semantics downstream.
  Not part of the preserved-verbatim unknown-TLV passthrough, so the loss is
  uncaught.

### 10. Received NOTIFICATION data is always discarded — CONFIRMED
- **File:** `src/notification.rs:450` (field at line 15)
- **Category:** correctness
- **Bug:** `NotificationPacket.data` is `#[nom(Ignore)]`, so the derived parse
  leaves it empty, and `parse_packet` reads the data bytes into a discarded
  `_data`. `packet.data` is always empty after parse.
- **Failure scenario:** A peer sends NOTIFICATION Cease/Administrative-Shutdown
  (code 6, subcode 2, RFC 9003) with a shutdown-communication string, or a
  header/OPEN/UPDATE error carrying the offending bytes. `take(len)` consumes them
  into `_data` and drops them → the operator/logs never see the diagnostic. A
  `NotificationPacket` built with data and re-parsed comes back with empty data.

### 11. COMMUNITIES / LARGE_COMMUNITY width not enforced — PLAUSIBLE
- **File:** `src/attrs/com.rs:54` (and `src/attrs/large_com.rs:68`)
- **Category:** robustness
- **Bug:** Both decode the payload as a nom `many0` of fixed-width values with no
  multiple-of-width check, and the attribute path discards the parser's leftover,
  so a non-multiple-of-4 (resp. 12) payload is accepted with trailing bytes
  silently dropped. `ClusterList` (`cluster_list.rs:28`) enforces its width; these
  do not.
- **Failure scenario:** A crafted UPDATE with a COMMUNITIES attribute of length 6
  parses one 4-byte community and silently discards the trailing 2 bytes; the
  malformed attribute is accepted and the route installed instead of RFC 7606
  treat-as-withdraw.

### 12. EVPN MAC/IP length fields validated leniently — PLAUSIBLE
- **File:** `src/attrs/nlri_evpn.rs:805` (also 810, 1076)
- **Category:** correctness
- **Bug:** EVPN Type-2 MAC/IP length fields are validated via
  `nlri_psize()==6/4/16` (a `div_ceil` on the bit count) rather than an exact
  bit-count; SMET/IGMP-sync source/group lengths accept any `nlri_psize`-consistent
  value.
- **Failure scenario:** A Type-2 route with `mac_len=41` has `nlri_psize()==6` and
  passes the `==6` check, reading 6 octets as the MAC; an `ip_len` of 200 gives
  `ip_size=25`, read-and-discarded so the route parses as MAC-only; a Type-6 SMET
  `group-len=25` is accepted as a 4-octet IPv4 group. No over-read (bounded by
  `take`), but malformed NLRI enters the RIB. (Type-3 at line 838 correctly
  hard-checks 32/128.)

### 13. `many0_complete` silently truncates the NLRI list — PLAUSIBLE
- **File:** `src/attrs/mp_reach.rs:435` (pattern also at `nlri_evpn.rs:758`,
  `aspath.rs:233`, and `mp_unreach.rs`)
- **Category:** robustness
- **Bug:** MP_REACH/MP_UNREACH NLRI lists are parsed with `many0_complete` and the
  caller discards the leftover, so an inner NLRI parse error — or an over-claimed
  length octet yielding `Err::Incomplete` — silently stops the list and drops the
  malformed route plus every valid route after it, with no full-consumption check.
- **Failure scenario:** A peer sends an MP_REACH whose NLRI block is
  `[valid][malformed][more valid]`; the parser returns `Ok` with only the leading
  prefixes and discards the rest and any trailing bytes, instead of RFC 7606
  treat-as-withdraw → route loss and smuggled hidden bytes with no error.

### 14. Flow-spec components accepted out-of-order / duplicated — PLAUSIBLE
- **File:** `src/attrs/nlri_flowspec.rs:562`
- **Category:** robustness
- **Bug:** The component loop accepts components in any order and with duplicate
  types; RFC 8955 §4.1 requires strictly ascending, non-repeating component types
  and mandates treating a violation as error/withdraw.
- **Failure scenario:** An attacker sends an NLRI whose components are descending
  (type 5 then type 3) or repeat a type; `parse()` accepts it and the resulting
  `FlowspecNlri` mis-sorts under the `Ord` used as the BTreeMap precedence key,
  letting a crafted route shadow or reorder higher-precedence dataplane rules.

### 15. UPDATE / attribute length truncated by `as u16` on emit — PLAUSIBLE
- **File:** `src/update.rs:518` (also 504; MP_REACH/MP_UNREACH and BGP-LS emit
  helpers)
- **Category:** correctness
- **Bug:** `From<UpdatePacket> for BytesMut` writes the header length and attr-len
  as `as u16` with no cap or pagination (unlike the paginating `pop_ipv4` path), so
  an UPDATE that serializes past 65535 bytes truncates the on-wire length. The same
  `len as u16` cast recurs across the MP emit helpers.
- **Failure scenario:** An UPDATE built via `update.into::<BytesMut>()`
  (`update_group.rs`, `peer_egress.rs`, `group_egress.rs`) with enough withdrawn
  routes/NLRIs to exceed 65535 serialized bytes wraps `buf.len() as u16`, emitting
  a bogus header length that desyncs the receiver's framing. Reachability depends
  on callers bounding message size — but there is no guard here.

---

## Below the cut (verified but not in the top 15)

**Lower-severity correctness**

- `src/attrs/flowspec_action.rs:71` — traffic-rate decoded as a raw `f32` from
  attacker bytes with no finite-value check; NaN/Inf rates decode as valid and
  reach the policer, and NaN breaks `PartialEq` for any dedup/compare.
- `src/attrs/srpolicy.rs:405` — Weight sub-TLV accepts `weight=0`, though the doc
  notes RFC 9256 makes it invalid; a `share = weight/total` consumer can divide by
  zero.
- `src/attrs/prefix_sid.rs:434` — `decode_srv6_service` splits SIDs and
  unknown-sub-TLVs into separate vecs and `emit_srv6_service` writes all SIDs
  first, so interleaved sub-TLV order is not preserved despite the "bit-exact
  round-trip" doc claim.
- `src/attrs/nlri_mup.rs:305` — `MupRoute::parse` never verifies the body consumed
  exactly the outer `Length` byte; trailing bytes inside the declared length are
  silently dropped (parse ambiguity).
- `src/attrs/mp_reach.rs:320` — the RFC 4760 "Number of SNPAs" octet is read as a
  reserved byte; a nonzero SNPA count misparses the following bytes as NLRI (no
  compliant peer sends nonzero, so robustness only).
- `src/parser.rs:66` — `peek_bgp_length` returns `Some(length)` without validating
  `>= 19` / `<= 4096`; the sole current caller re-checks, so latent.
- `src/route_refresh.rs:36` — `parse_packet` never validates `header.length` nor
  rejects trailing in-message bytes.
- Emit `as u8`/`as u16` truncation, latent behind message-size caps:
  `nlri_bgpls.rs:675`, `bgpls_attr.rs:153`, `nlri_evpn.rs:1361` (LeafAd),
  `nlri_mup.rs:663`, `prefix_sid.rs:407`, `srpolicy.rs:537`, `nlri_flowspec.rs:772`.

**Cleanup / altitude (reuse & duplication)**

- `RouteDistinguisher` has a centralized `parse_be` but its wire encoding is
  hand-rolled at ~22 sites across 5 files (no `RouteDistinguisher::emit`) —
  `nlri_evpn.rs` (12), `nlri_mup.rs` (4), `nlri_vpnv4.rs`/`nlri_vpnv6.rs` (3 each).
  The two halves of the codec live at different altitudes.
- The MP_REACH/MP_UNREACH attribute trailer (buffer value → compute extended flag
  → put flags/type/len/value) is copy-pasted ~16 times across `mp_reach.rs` /
  `mp_unreach.rs`; `AttrEmitter::attr_emit` in `src/attrs/emitter.rs` already does
  it. A missed copy silently emits a malformed attribute for one SAFI.
- The labeled/VPN prefix parse body (plen floor check, 3-byte label, `plen -= hdr`,
  `psize` guards, copy into `[0u8;N]`) is copy-pasted ~9 times across
  `nlri_labeled_unicast.rs`, `nlri_vpnv4.rs`, `nlri_vpnv6.rs`, `nlri_ipv4.rs`,
  `nlri_ipv6.rs`, `nlri_mup.rs`; add shared `parse_v4_prefix`/`parse_v6_prefix`.
- The per-AFI/SAFI MP next-hop framing (`match nhop_len {4/16/32}`) is copy-pasted
  ~10 times in one `parse_nlri_opt` if-chain, and behavior already drifts between
  copies (EVPN/RTC/LinkState reject the RFC 8950 32-octet form the others accept).
- `src/update.rs` — `pop_evpn`/`pop_srpolicy`/`pop_vpnv6`/`pop_vpnv4` repeat the
  same ~25-line UPDATE framing scaffold.
- `src/util.rs` `u32_u24` duplicates `packet_utils::u32_u8_3`; `src/parse_be.rs`
  re-declares `packet-utils`' `ParseBe` trait + `Ipv4Addr` impl; `prefix_sid.rs`
  `parse_be_u24`/`put_be_u24` re-implement `nom::number::complete::be_u24` /
  `crate::u32_u24`.

---

## Notes on method

- No pending diff existed; this reviews the committed crate as of 2026-07-16.
- Memory-safety/panic hunting across the parsers came back clean — the residual
  issues are validation leniency, encode/parse asymmetry, and emit-side length
  casts, not over-reads.
- CONFIRMED findings were checked directly against the source; PLAUSIBLE findings
  have a real mechanism whose trigger depends on peer capability, config, or
  message size.
