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

## Deferred work

### Drive `as4` from capability negotiation (RFC 6793) — AGREED, DEFERRED

**Decision:** agreed to do this, deliberately not now. Recorded here so the
context found while fixing finding 5 is not lost.

**What is wrong today.** `peer_packet_parse`
(`zebra-rs/src/bgp/peer.rs:2459`) calls
`BgpPacket::parse_packet(rx, true, Some(opt.clone()))` — the `as4` argument is a
hardcoded `true`, never sourced from what the peer actually negotiated.
`Peer::as4` (`peer.rs:909`) exists but is set `true` at construction
(`peer.rs:1120`) and never assigned anywhere. So zebra-rs always decodes AS_PATH
as 4-octet, whatever the peer advertised.

**Consequence.** A genuine OLD (non-AS4) speaker sends 2-octet AS_PATHs per
RFC 6793. zebra-rs would read the segment header and then consume 4 octets per
ASN, overrunning the attribute — a misparse, not a clean rejection. Rare in
practice (AS4 is effectively universal), which is why this is deferred rather
than urgent.

**Why it is a feature, not a one-line change.** Setting `as4 = false` for such a
peer is necessary but *not sufficient*, and on its own would lose information:

1. `as4` must come from the negotiated capability, per peer/connection — the
   value has to reach `peer_packet_parse`, which currently has no peer context
   at that call site.
2. **AS4_PATH (type 17)** and **AS4_AGGREGATOR (type 18)** must be implemented.
   Neither exists in `AttrType` (`attrs/attr.rs:14`) today. An OLD peer puts
   AS_TRANS (23456) in the 2-octet AS_PATH as a placeholder and carries the real
   4-octet ASNs in AS4_PATH; without it the true AS numbers are unrecoverable.
3. The RFC 6793 §4.2.3 **merge algorithm** (reconcile AS_PATH with AS4_PATH,
   preferring AS_PATH's hop count) must be implemented.
4. The **emit** side needs the mirror: `Attr::emit` has no `As2Path` arm, so
   advertising a 2-octet AS_PATH (with AS_TRANS substitution) to an OLD peer is
   also unimplemented.

**Already in place.** `From<As2Path> for As4Path` (`attrs/aspath.rs`) and the
`Attr::As2Path` arm (`attrs/attr.rs`) now widen a 2-octet AS_PATH into the
4-octet form instead of dropping it, so step 1 above cannot silently lose
AS_PATHs the moment `as4` starts varying. `AS_TRANS` is already defined
(`aspath.rs:21`, currently `#[allow(dead_code)]`). Widening keeps AS_TRANS
literal until AS4_PATH lands.

**Trap to remember.** `As4Path` has an inherent `pub fn from(asn: Vec<u32>)`
(`aspath.rs:452`) that shadows `From::from`, so `As4Path::from(as2_path)`
silently resolves to the wrong function; use `.into()`.

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

### 2. Type-2 (4-octet-AS) Route Distinguisher fails to parse — CONFIRMED — ✅ FIXED
- **File:** `src/attrs/rd.rs:8`
- **Category:** correctness
- **Status:** Fixed on branch `fix-bgp-cap-unknown-header`. Reproduced first: a
  type-2 RD returned `Err(Error { code: Switch })` while types 0/1 parsed.
  `RouteDistinguisherType` gained an `ASN4 = 2` variant; `Display` became an
  exhaustive match (the old `if ASN {..} else {..}` would have rendered a type-2
  RD as IPv4); `FromStr` now accepts the 4-byte-AS text form (type 0 still wins
  when the AS fits in 16 bits); `From<RouteDistinguisher> for ExtCommunityValue`
  maps ASN4 → high_type 0x02 (RFC 5668); and `inst.rs`'s reverse extcomm → RD
  mapping now sends high_type 0x02 → ASN4 so a configured 4-byte-AS RT actually
  intersects the same RT on the wire.

  Follow-up (same branch): 4-byte-AS text notation reconciled with RFC 5396.
  `FromStr` now accepts **both** asplain (`4200000000:1`, IOS-XR's default and
  RFC 5396's recommendation) and asdot (`64086.59904:1`, IOS-XR under
  `as-format asdot`, and the only form GoBGP emits); a dotted AS selects type 2
  explicitly, mirroring GoBGP's `ParseRouteDistinguisher`. A 4-byte AS is now
  spelled the same way in RD/RT and AS_PATH show output — previously
  `asn_to_string` used asdot while the RD `Display` used asplain. A shared
  `asn_from_string` in `attrs/aspath.rs` pairs with `asn_to_string`.

  Type-2 `Display` uses **asdot+** (always dotted), not plain asdot. In the
  overlap where both the AS and the assigned number fit in 16 bits, the dot is
  the only thing distinguishing type 2 from type 0, so it has to survive
  display: plain asdot drops it below 65536, which made `0.100:1` print as
  `100:1` and read back as type 0 — the type silently flipped. asdot+ is
  byte-identical to asdot for any AS >= 65536 (every real 4-byte AS), and
  matches GoBGP's `RouteDistinguisherFourOctetAS.String()`.
  `asn_to_asdot_plus` sits beside `asn_to_string`, and
  `display_round_trips_preserving_type` pins every type against regression.
- **Bug:** `RouteDistinguisherType` models only `ASN = 0` and `IP = 1` with no
  catch-all variant, so the derived `NomBE` parser errors on any other RD type.
- **Failure scenario:** A peer advertises a VPNv4/VPNv6/EVPN/MUP route whose RD is
  type 2 (4-byte AS : 2-byte number, RFC 4364 — standard whenever the AS is
  4-byte). `RouteDistinguisher::parse_be` reads `typ=2`, finds no matching enum
  variant → nom error → the enclosing `Vpnv4Nlri`/`Vpnv6Nlri` parse fails →
  `many0_complete` silently drops that route. Type-2-RD VPN routes are never
  installed.

### 3. AS_SEQ segment count truncated by `as u8` — CONFIRMED — ✅ FIXED
- **File:** `src/attrs/aspath.rs:126` (with `prepend_mut` at 447-462,
  `consolidate` at 579)
- **Category:** correctness
- **Status:** Fixed on branch `fix-bgp-cap-unknown-header`. Reproduced first: a
  256-ASN AS_SEQ emitted `count = 0` followed by 1024 ASN bytes, and
  `prepend_mut` on a 255-ASN path was confirmed to produce exactly that
  (`1 segment, 256 ASNs -> count byte = 0`). `As4Segment::emit` now splits at
  the new `AS_SEGMENT_MAX` (255) into consecutive segments of the same type,
  mirroring FRR's `aspath_put`, so 256 ASNs emit as `255 + 1` and the peer
  reconstructs the identical ASN sequence. The empty-segment encoding is
  preserved explicitly (`chunks` yields nothing for an empty slice). Fixed in
  the emitter rather than in `prepend_mut`/`consolidate` so every producer is
  covered and the in-memory path stays one logical segment.
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

### 4. RTC parser rejects the `plen=0` default membership it emits — CONFIRMED — ✅ FIXED
- **File:** `src/attrs/nlri_rtcv4.rs:24` (and `src/attrs/nlri_rtcv6.rs:29`)
- **Category:** correctness
- **Status:** Fixed on branch `fix-bgp-cap-unknown-header`, together with
  finding 8 (below), which is the same emit/parse asymmetry in the same file.
  Reproduced first: `plen=0` and `plen=32` both returned `Err(LengthValue)`
  while `plen=96` parsed, and a default membership ahead of an exact RT killed
  the whole list.

  **Severity correction:** the original failure scenario was wrong. Because the
  parse error left `updates` empty and nothing was inserted into `peer.rtcv4`,
  and every filter site is gated on `!peer.rtcv4.is_empty()`, a received default
  membership actually resulted in advertising *everything* — accidentally the
  correct outcome. The real defects were (a) a default membership ahead of other
  NLRI discarded them via `many0_complete`, and (b) partial prefixes (32..95,
  legal per RFC 4684 §4) were rejected outright, which over-advertises when the
  partial comes first and under-advertises when it comes later.

  `parse_nlri` now accepts `0` and `32..=96`, consuming exactly `ceil(plen/8)`
  octets, and records `plen`; `rt` is only populated for a full 96-bit prefix
  (mirroring GoBGP, which leaves `RouteTarget` nil below 96). v4 and v6 now
  share one `parse_rtc_membership`/`emit_rtc_membership` pair, since the NLRI is
  byte-identical across families.

  Consumer guarded against regression: `route_ipv4_rtc_update` inserts only
  fully specified (`is_exact()`) RTs. Naively inserting a default membership's
  zero RT would have made the set non-empty and flipped us from advertising
  everything to advertising **nothing**. Failing open is the safe direction —
  RTC is an optimisation, so over-advertising costs bandwidth while
  under-advertising blackholes VPN routes.
- **Known gap (documented in code, not fixed):** a peer mixing an exact RT with
  a default or partial membership is still filtered to the exact one, because
  "wants everything" has no representation distinct from "said nothing".
  Expressing it needs a flag threaded through all seven filter sites; no
  implementation sends that combination.
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

### 5. Non-AS4 peer's AS_PATH silently discarded — ⚠️ NOT REACHABLE (verdict corrected) — ✅ arm fixed anyway
- **File:** `src/attrs/attr.rs:410`
- **Category:** correctness
- **Status / verdict correction:** The code defect is real — the arm was an empty
  `// TODO` that dropped a parsed AS_PATH — but the **stated failure scenario
  cannot happen**, and the CONFIRMED verdict was wrong. `peer_packet_parse`
  (`zebra-rs/src/bgp/peer.rs:2459`) calls `BgpPacket::parse_packet(rx, true, ..)`
  with `as4` **hardcoded to `true`**, never sourced from capability negotiation.
  `peer.as4` exists but is set `true` at construction and never assigned. So
  AS_PATH always parses as `As4Path`, `Attr::As2Path` is never constructed at
  runtime (only tests pass `as4=false`), and `Attr::emit` has no `As2Path` arm
  either. No route has ever lost its AS_PATH this way.

  Fixed regardless, as trap removal: `Attr::As2Path` now widens into `As4Path`
  via a new `From<As2Path> for As4Path` (RFC 6793 §4.2.2, zero-extending each
  ASN, hop count preserved). Wiring `as4` to the negotiated capability would
  otherwise have silently started dropping AS_PATHs. Zero runtime behaviour
  change today.
- **The real latent bug this exposed — agreed and deferred:** `as4` is hardcoded
  `true`, so a genuine OLD (non-AS4) peer's 2-octet AS_PATH would be misparsed as
  4-octet. Driving `as4` from capability negotiation is agreed as future work;
  see **[Deferred work → Drive `as4` from capability negotiation
  (RFC 6793)](#drive-as4-from-capability-negotiation-rfc-6793--agreed-deferred)**
  at the top of this document for the full scope (AS4_PATH type 17,
  AS4_AGGREGATOR type 18, the §4.2.3 merge, and the emit side).
- **Also noted:** `As4Path` has an inherent `pub fn from(asn: Vec<u32>)`
  (`aspath.rs:452`) that shadows `From::from`, so `As4Path::from(as2_path)`
  silently resolves to the wrong function and callers must use `.into()`.
- **Bug:** The `Attr::As2Path(_v) => { // TODO }` arm drops a parsed 2-octet
  AS_PATH, leaving `bgp_attr.aspath = None`.
- **Failure scenario:** A legacy peer that did not negotiate the AS4 capability
  sends a normal UPDATE; `parse_attr_value` runs with `as4=false`, so the AS_PATH
  is parsed as `As2Path` and then dropped. The route is installed with **no
  AS_PATH** (loop detection and AS-path-length best-path comparison broken) and is
  re-advertised without one, instead of being converted to 4-byte form or rejected
  as a missing well-known-mandatory attribute.

### 6. IPv6 extended community local-admin emitted native-endian — CONFIRMED (code) / NOT REACHABLE (scenario) — ✅ FIXED
- **File:** `src/attrs/ext_ipv6_com.rs:68`
- **Category:** correctness
- **Status / verdict correction:** The coding defects are all real and are fixed,
  but the stated failure scenario **cannot happen**: `ExtIpv6Community` has no
  references outside its own module, so nothing ever calls `from_str`, `new()` or
  `encode()`. The whole module is unwired. Fixed as trap removal, exactly as
  finding 5 was: `to_ne_bytes` → `to_be_bytes`; `Display` rewritten to the
  RFC 5701 §2 layout `new()` actually writes (16-octet IPv6 Global Administrator
  + 2-octet Local Administrator) instead of the 8-octet AS/IPv4 layouts it was
  reading; and `from_str`'s `tokenizer(..).unwrap()` → `map_err(|_| ())?` so it
  honours its declared `Err(())` instead of panicking.
- **The live bug this investigation exposed — ✅ FIXED, and far more severe:**
  `AttrType` named `ExtendedIpv6Com = 25` with **no matching `Attr` variant** —
  the only such code in the enum. A recognized-but-unhandled type does not match
  `AttrType::Unknown`, so it skipped the RFC 4271 §9 handling, reached
  `parse_attr_value`, failed the derived Switch with no arm to select, and — not
  being a treat-as-withdraw attribute — propagated the error out as a **session
  reset**. Any peer sending an RFC 5701 IPv6 extended community tore the session
  down. Proven before the fix:

  ```
  type 25  (IPv6 ext-community, optional+transitive) -> ERR (session reset)
  type 200 (unallocated,        optional+transitive) -> OK, unknown_attrs=1
  ```

  An attribute zebra-rs half-recognized was strictly worse than one it did not
  recognize at all. Code 25 is now unnamed, so it decodes as `Unknown(25)` and
  takes the §9 optional-transitive path: retained with the Partial bit and
  propagated. A comment where the variant used to sit records the invariant —
  every code named in `AttrType` must have a matching `Attr` variant — so it is
  not naively re-added.
- **Deferred:** real RFC 5701 support (an `Attr::ExtendedIpv6Com` variant, a
  `BgpAttr` field, an `AttrEmitter`, and RT matching against IPv6 route-targets)
  is a feature, not a bug fix. The `ext_ipv6_com` module is the skeleton for it
  and is now correct; passing the attribute through per §9 is the right
  behaviour until then.
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

### 7. Flow-spec op-list overruns into the next component — PLAUSIBLE — ✅ FIXED (as far as the encoding allows)
- **File:** `src/attrs/nlri_flowspec.rs:168`
- **Category:** correctness
- **Status:** Fixed on branch `fix-bgp-cap-unknown-header`. The comment was
  indeed false: `FlowspecNlri::parse` hands `parse_component` (and so
  `parse_op_list`) the **whole remaining NLRI value**, not a per-component
  slice, so "the component slice is exhausted, so a missing end bit can't run
  into the next component" claimed a guarantee that does not exist. There is no
  per-component length anywhere in the flow-spec encoding — the end-of-list bit
  is the only delimiter.

  Split the problem in two. **Detectable:** a term list reaching the end of the
  NLRI without ever setting the end bit. RFC 8955 §4.2 makes the bit mandatory
  on the final term, and `parse_op_list` also terminated on exhaustion, so such
  a list was silently accepted. Reproduced:

  ```
  [03 03 01 06]  (op 0x01, no end bit) -> ACCEPTED, parsed "proto =6"
  re-emit        [03 03 81 06]          -> end bit silently added
  ```

  Because `emit_op_list` re-derives the bit from position, a route reflector
  would propagate octets it never received. Now rejected, matching GoBGP, whose
  `FlowSpecComponent` decoder only ever breaks on the end bit and errors when
  the data runs out without it. **Undetectable:** a list missing the bit
  mid-NLRI whose stolen octets happen to decode as further terms, one of which
  sets the bit. No parser can tell — the components silently mis-frame. This is
  inherent to the encoding and is now documented rather than wrongly claimed
  impossible.
- **Trade-off accepted:** strictness rejects an NLRI that the lenient path
  recovered the correct meaning from (the end-of-NLRI case above), and finding
  13's `many0_complete` then silently drops it *and every NLRI after it*. That
  is the right layering — the parser reports malformed input; the caller's
  RFC 7606 handling is separately broken — but it means finding 13 makes this
  bite harder than it should. Accepting octets the RFC forbids is the wrong
  default for a filter that decides which traffic gets dropped.
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

### 8. RTC withdraw emitter omits prefix-length and origin-AS — CONFIRMED (latent) — ✅ FIXED
- **File:** `src/attrs/nlri_rtcv4.rs:116` (and `src/attrs/nlri_rtcv6.rs:121`)
- **Category:** correctness
- **Status:** Fixed alongside finding 4 (same file, same emit/parse asymmetry).
  Both Unreach emitters now call the shared `emit_rtc_membership`, so a withdraw
  is encoded exactly as the parser reads it. No behaviour change today — the
  path stays dormant until a non-empty RTC withdraw is wired — but the hand-
  rolled encoder could not be left beside the shared one.
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
