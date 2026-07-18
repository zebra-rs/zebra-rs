# bgp-packet Code Review Findings

**Review date:** 2026-07-16
**Re-evaluated:** 2026-07-17 — every one of the original 15 ranked findings is
fixed and merged to `main` (the `fix-bgp-cap-unknown-header` series,
`a2c21ea8..4b265a9b`). This pass re-verified each remaining item against the
current tree — line numbers below are current — and re-ranked what is still
open. Fixed findings are out of scope for the ranking and are condensed in
**[Fixed](#fixed-out-of-scope-for-the-ranking)** at the end.
**Scope:** whole-crate review of `crates/bgp-packet/` (committed tree; no
pending diff)
**Effort:** xhigh recall — 10 finder angles fanned across every file,
candidates adversarially verified, ranked most-severe first.

## Summary

The crate's **parse paths are well hardened against memory-safety bugs** —
every angle hunting panics / over-reads on malicious input came back clean, and
the fix series strengthened the validation posture further (exact-consumption
NLRI blocks, RFC 7606 treat-as-withdraw for community widths, exact bit-length
checks in EVPN, mandatory flow-spec end-of-list bit).

With the original 15 findings fixed, what remains open falls into three bands:

1. **Two agreed-but-deferred interop features** — driving `as4` from capability
   negotiation (RFC 6793) and real RFC 5701 IPv6-extended-community support.
   These are features, not one-line fixes; both have their groundwork already
   landed.
2. **One newly promoted interop defect** — the MP next-hop framing drift: the
   EVPN, RTC and BGP-LS arms reject the 32-octet (global + link-local) next hop
   the other arms accept, and a rejected next hop propagates as a session
   reset. Previously buried in the cleanup list; it is the only open item where
   a *conformant* peer message can still tear a session down.
3. **Latent emit casts and low-severity robustness** — the attribute-level
   `len as u16` casts (blocked on making `AttrEmitter` fallible), and the
   below-the-cut leftovers (weight=0, non-finite flow-spec rates, missing
   trailing-byte checks), none of which a compliant peer can trigger today.

## Open findings (re-ranked 2026-07-17)

### O1. Drive `as4` from capability negotiation (RFC 6793) — AGREED, DEFERRED
- **File:** `zebra-rs/src/bgp/peer.rs:2472` (crate side: `src/attrs/aspath.rs`,
  `src/attrs/attr.rs`)
- **Category:** correctness / interop
- **What is wrong today.** `peer_packet_parse` calls
  `BgpPacket::parse_packet(rx, true, Some(opt.clone()))` — the `as4` argument
  is a hardcoded `true`, never sourced from what the peer actually negotiated.
  `Peer::as4` exists but is set `true` at construction and never assigned. So
  zebra-rs always decodes AS_PATH as 4-octet, whatever the peer advertised.
- **Consequence.** A genuine OLD (non-AS4) speaker sends 2-octet AS_PATHs per
  RFC 6793. zebra-rs would read the segment header and then consume 4 octets
  per ASN, overrunning the attribute — a misparse, not a clean rejection. Rare
  in practice (AS4 is effectively universal), which is why this is deferred
  rather than urgent.
- **Why it is a feature, not a one-line change.** Setting `as4 = false` for
  such a peer is necessary but *not sufficient*:
  1. `as4` must come from the negotiated capability, per peer/connection — the
     value has to reach `peer_packet_parse`, which currently has no peer
     context at that call site.
  2. **AS4_PATH (type 17)** and **AS4_AGGREGATOR (type 18)** must be
     implemented. Neither exists in `AttrType` today. An OLD peer puts
     AS_TRANS (23456) in the 2-octet AS_PATH as a placeholder and carries the
     real 4-octet ASNs in AS4_PATH; without it the true AS numbers are
     unrecoverable.
  3. The RFC 6793 §4.2.3 **merge algorithm** (reconcile AS_PATH with AS4_PATH,
     preferring AS_PATH's hop count) must be implemented.
  4. The **emit** side needs the mirror: `Attr::emit` has no `As2Path` arm, so
     advertising a 2-octet AS_PATH (with AS_TRANS substitution) to an OLD peer
     is also unimplemented.
- **Already in place** (landed while fixing original finding 5):
  `From<As2Path> for As4Path` and the `Attr::As2Path` arm widen a 2-octet
  AS_PATH into the 4-octet form instead of dropping it, so step 1 cannot
  silently lose AS_PATHs the moment `as4` starts varying. `AS_TRANS` is
  already defined (`aspath.rs`, currently `#[allow(dead_code)]`).
- **Trap to remember.** `As4Path` has an inherent `pub fn from(asn: Vec<u32>)`
  that shadows `From::from`, so `As4Path::from(as2_path)` silently resolves to
  the wrong function; use `.into()`.

### O2. MP next-hop framing drift — EVPN/RTC/BGP-LS reject the 32-octet form — CONFIRMED (promoted from cleanup)
- **File:** `src/attrs/mp_reach.rs:413` (EVPN), `:471` (RTCv4), `:512`
  (RTCv6), `:568` (BGP-LS)
- **Category:** correctness / interop
- **Bug:** The per-AFI/SAFI next-hop framing (`match nhop_len { 4/16/32 }`) is
  copy-pasted ~10 times through `parse_nlri_opt`, and the copies have drifted:
  the IPv6-unicast, labeled-unicast, MUP and SR-Policy arms accept the
  RFC 2545 32-octet next hop (global + link-local), while the EVPN, RTCv4,
  RTCv6 and BGP-LS arms hard-reject anything but 4/16.
- **Failure scenario:** A peer that includes the link-local next hop on one of
  the rejecting AFI/SAFIs (RFC 2545 §3 explicitly defines the 32-octet form;
  implementations emit it whenever a link-local is present) fails the
  MP_REACH parse. MP_REACH is deliberately *not* in the treat-as-withdraw set
  (RFC 7606 §3(j)), so the error propagates as a **session reset** — and will
  recur on every retry, wedging the session. This is the only open item where
  a conformant message still tears a session down.
- **Why promoted:** originally listed as duplication cleanup; the drift is the
  real defect and the dedup is the fix. One shared next-hop-framing helper
  (beside `parse_nlri_block` in `src/parser.rs`) removes both.

### O3. Attribute-level emit length casts — `len as u16` / `len as u8` with no clamp — LATENT (finding 15 residual)
- **Files:** `src/attrs/mp_reach.rs:858` (+7 more), `src/attrs/mp_unreach.rs`
  (8 sites), `src/attrs/nlri_bgpls.rs:184,316,494,675`,
  `src/attrs/bgpls_attr.rs:153`, `src/attrs/nlri_evpn.rs:1153-1377` (per-route
  length octet), `src/attrs/nlri_mup.rs:663` (`as u8`),
  `src/attrs/prefix_sid.rs:406`, `src/attrs/srpolicy.rs:595-597`
- **Category:** robustness
- **Bug:** The UPDATE-level wrap was fixed (`UpdatePacket::try_emit`,
  `UpdateEmitError::TooLong` — original finding 15), but the attribute-level
  casts remain: each emit helper writes its value length with a bare cast and
  no cap, so an over-long attribute body would wrap the length field.
- **Why still open:** fixing these means making the `AttrEmitter` trait
  fallible, which cascades through every attribute emitter. Bounded in
  practice by the callers' chunking — `pop_ipv4`/`pop_ipv4_mp_reach` bound
  `buf.len()` to `max_packet_size` ≤ 65535 and are safe by construction — so
  latent, not live. Doing this refactor is also the natural moment to collapse
  the ~16 copy-pasted MP attribute trailers (see cleanup below): same trait
  change, same files.

### O4. Real RFC 5701 IPv6-extended-community support — DEFERRED FEATURE (finding 6 residual)
- **Files:** `src/attrs/attr.rs:31` (invariant comment), `src/attrs/ext_ipv6_com.rs`
- **Category:** feature / interop
- **Current state (correct, minimal):** code 25 is deliberately *unnamed* in
  `AttrType`, so it decodes as `Unknown(25)` and takes the RFC 4271 §9
  optional-transitive path — retained with the Partial bit and propagated.
  The `ext_ipv6_com` module is a correct but unwired skeleton (endian,
  display and panic bugs fixed).
- **What full support needs:** an `Attr::ExtendedIpv6Com` variant, a `BgpAttr`
  field, an `AttrEmitter`, and RT matching against IPv6 route-targets. Matters
  once IPv6-address-specific route targets are used for VPN import/export.
- **Invariant to keep:** every code named in `AttrType` must have a matching
  `Attr` variant — a half-recognized code skips the §9 unknown-attribute path
  and becomes a session reset (that was the live bug here, fixed in
  `e97589e1`).

### O5. `MupRoute::parse` never checks full consumption of the declared length — CONFIRMED
- **File:** `src/attrs/nlri_mup.rs:299`
- **Category:** correctness (parse ambiguity)
- **Bug:** `parse` takes `length` octets into `body_slice`, parses the
  route-type body out of it, and returns without verifying the body consumed
  `body_slice` exactly (`rest.is_empty()` is asserted only in tests). Trailing
  bytes inside the declared length are silently ignored.
- **Failure scenario:** Two different wire encodings (with and without
  trailing garbage) parse to the same `MupRoute`, so route identity is
  ambiguous and a re-emit is not byte-identical to what was received. MUP is
  actively used here (T-Mup/cradle datapath), which is why this outranks the
  remaining robustness items.

### O6. RTC mixed exact + default/partial membership filtered to the exact RT — KNOWN GAP (finding 4 residual, documented in code)
- **File:** `src/attrs/nlri_rtcv4.rs` / consumers in `zebra-rs/src/bgp`
- **Category:** correctness (documented limitation)
- **Gap:** a peer mixing an exact RT with a default (`plen=0`) or partial
  membership is still filtered to the exact one, because "wants everything"
  has no representation distinct from "said nothing" — only `is_exact()` RTs
  enter `peer.rtcv4`. Expressing it needs a flag threaded through all seven
  filter sites. No known implementation sends that combination, and the
  failure direction is over-advertising (safe for RTC), so this stays low.

### O7. Flow-spec traffic-rate decoded as raw `f32` with no finite check — PLAUSIBLE
- **File:** `src/attrs/flowspec_action.rs:71,75`
- **Category:** robustness
- **Bug:** `as_flowspec_action` builds `TrafficRateBytes`/`TrafficRatePackets`
  from attacker-controlled bytes with `f32::from_be_bytes` and no
  `is_finite()` check; NaN/Inf rates decode as valid.
- **Severity reduced since the review:** the type is now documented as
  interpretation-only ("f32 rates are not `Eq`/`Ord`"), so the original
  dedup/compare concern is designed away. The residual risk is a NaN/Inf rate
  reaching a future policer consumer; clamp or reject at decode when one is
  wired.

### O8. SR Policy Weight sub-TLV accepts `weight = 0` — CONFIRMED (low)
- **File:** `src/attrs/srpolicy.rs:461`
- **Category:** robustness
- **Bug:** `parse_weight` validates only the 6-octet length; RFC 9256 makes a
  zero weight invalid, and a `share = weight / total` consumer can divide by
  zero when all segment-list weights are 0.

### O9. SRv6 service sub-TLV interleaving not preserved on re-emit — CONFIRMED (low)
- **File:** `src/attrs/prefix_sid.rs:295` (decode), `:410` (emit)
- **Category:** robustness
- **Bug:** `decode_srv6_service` splits SID-information sub-TLVs and unknown
  sub-TLVs into separate vecs, and `emit_srv6_service` writes all SIDs first,
  so an input interleaving unknown sub-TLVs between SIDs re-emits in a
  different order — despite the module's bit-exact-round-trip claim. TLV order
  is not semantically significant per RFC 9252, and no known sender
  interleaves, so low.

### O10. ROUTE_REFRESH parse skips length / trailing-byte validation — CONFIRMED (low)
- **File:** `src/route_refresh.rs:36`
- **Category:** robustness
- **Bug:** `parse_packet` is a bare `parse_be` — it neither validates
  `header.length == 23` nor rejects trailing in-message bytes, so a
  ROUTE_REFRESH with a padded body parses as if well-formed (RFC 7313 §6 wants
  it treated as malformed).

### O11. `peek_bgp_length` returns unvalidated lengths — LATENT (low)
- **File:** `src/parser.rs:95`
- **Category:** robustness
- **Bug:** returns `Some(length)` without validating `>= 19` / `<= 4096`; the
  sole current caller re-checks, so this is only a trap for a future caller.

### O12. MP_REACH Reserved/SNPA octet — STATUS CHANGED, effectively closed (lowest)
- **File:** `src/attrs/mp_reach.rs:238` (and each arm)
- **Category:** robustness (obsolete-peer interop)
- **Current state:** the octet is now read, modeled per-variant (`snpa: u8`)
  and preserved on re-emit — per RFC 4760 it is a Reserved octet that MUST be
  0 and is ignored on receipt, which this satisfies. Residual quibbles only:
  a pre-RFC-4760 (RFC 2858) peer sending a nonzero SNPA *list* would misframe
  the NLRI — now surfaced loudly by the strict `parse_nlri_block` rather than
  silently misparsed — and re-emitting a preserved nonzero octet technically
  violates the transmission MUST. No action planned unless an RFC 2858 peer
  materialises.

---

## Cleanup / altitude (open)

- `RouteDistinguisher` has a centralized `parse_be` but still no `emit`; its
  wire encoding is hand-rolled at ~22 sites across 5 files — `nlri_evpn.rs`
  (12), `nlri_mup.rs` (4), `nlri_vpnv4.rs`/`nlri_vpnv6.rs` (3 each). The two
  halves of the codec live at different altitudes.
- The MP_REACH/MP_UNREACH attribute trailer (buffer value → compute extended
  flag → put flags/type/len/value) is copy-pasted 16 times (8 per file;
  verified by grep). `AttrEmitter::attr_emit` already does it. A missed copy
  silently emits a malformed attribute for one SAFI. Fold into the O3
  fallible-emitter refactor — same trait, same files.
- The labeled/VPN prefix parse body (plen floor check, 3-byte label,
  `plen -= hdr`, `psize` guards, copy into `[0u8;N]`) is still copy-pasted
  ~9 times across `nlri_labeled_unicast.rs`, `nlri_vpnv4.rs`,
  `nlri_vpnv6.rs`, `nlri_ipv4.rs`, `nlri_ipv6.rs`, `nlri_mup.rs`; add shared
  `parse_v4_prefix`/`parse_v6_prefix` beside `parse_nlri_block`.
- The per-AFI/SAFI next-hop framing duplication is now **O2** — the drift
  between copies is a ranked interop defect, not just cleanup.
- `src/update.rs` — `pop_evpn`/`pop_srpolicy`/`pop_srpolicy_withdraw`/
  `pop_vpnv6`/`pop_vpnv4` still repeat the same ~25-line UPDATE framing
  scaffold.
- `src/util.rs` `u32_u24` duplicates `packet_utils::u32_u8_3`;
  `src/parse_be.rs` re-declares `packet-utils`' `ParseBe` trait + `Ipv4Addr`
  impl; `prefix_sid.rs` `parse_be_u24`/`put_be_u24` re-implement
  `nom::number::complete::be_u24` / `crate::u32_u24`.
- *(Resolved by the fix series: the 25-site `many0_complete` NLRI duplication
  is gone — all sites now go through the shared `parse_nlri_block`.)*

---

## Fixed (out of scope for the ranking)

All 15 originally ranked findings, fixed on `fix-bgp-cap-unknown-header` and
merged to `main`; each fix landed with regression tests. Condensed here —
full analysis lives in the git history of this file (`ed5495bd..3a3aa5ce`).

1. **Unknown capability with 0/1-octet body broke session establishment**
   (`caps/unknown.rs`) — `CapUnknown` re-parsed a 2-byte header already
   consumed by `parse_cap`, so an RFC 9234 Role capability (len 1) failed the
   whole OPEN. Now `#[nom(Ignore)] code` + raw `data`, per RFC 5492
   ignore-unknown. — `a2c21ea8`
2. **Type-2 (4-octet-AS) Route Distinguisher unparseable** (`attrs/rd.rs`) —
   no `ASN4 = 2` variant, so type-2 VPN routes were dropped. Added end-to-end:
   parse, exhaustive `Display`, `FromStr` accepting both asplain and asdot
   (RFC 5396), and RFC 5668 extcomm mapping in both directions. Type-2
   displays as **asdot+** (always dotted) — below 65536 the dot is the only
   thing distinguishing type 2 from type 0 across a display round-trip.
   — `dd0dcfc6`, `5e71477c`, `9a37cd72`
3. **AS_SEQ segment count wrapped at 256 ASNs** (`attrs/aspath.rs`) —
   `prepend_mut` on a 255-ASN path emitted `count = 0` + 1024 orphan bytes →
   peer NOTIFICATION. `As4Segment::emit` now splits at 255 into consecutive
   same-type segments, mirroring FRR's `aspath_put`. — `1c06d0cc`
4. **RTC parser rejected the `plen=0` default membership it emits, and all
   partial prefixes** (`attrs/nlri_rtcv4.rs`/`v6`) — now accepts `0` and
   `32..=96` (RFC 4684 §4), shared `parse_rtc_membership`/`emit_rtc_membership`
   across v4/v6; only `is_exact()` RTs enter `peer.rtcv4` so a default
   membership fails open (over-advertise, never blackhole). Residual gap →
   **O6**. — `031e2c1d`
5. **`Attr::As2Path` arm dropped a parsed 2-octet AS_PATH** (`attrs/attr.rs`)
   — verdict corrected to NOT REACHABLE (`as4` is hardcoded `true`, so the arm
   never ran); fixed anyway as trap removal by widening into `As4Path` per
   RFC 6793 §4.2.2. The real latent issue → **O1**. — `fa37f1d3`, `c0ce7066`,
   `1dd03278`
6. **AttrType 25 half-recognition reset the session** (`attrs/attr.rs`,
   `attrs/ext_ipv6_com.rs`) — a named-but-unhandled code skipped the RFC 4271
   §9 unknown path and errored out as a session reset on any RFC 5701 IPv6
   extended community. Code 25 is now unnamed → `Unknown(25)` → §9
   passthrough; the skeleton module's endian/display/panic bugs fixed. Full
   RFC 5701 support → **O4**. — `e97589e1`
7. **Flow-spec op-list could run past its component** (`nlri_flowspec.rs`) —
   a term list reaching end-of-NLRI without the RFC 8955 §4.2 end-of-list bit
   was silently accepted (and the bit silently added on re-emit). Now
   rejected, matching GoBGP; mid-NLRI mis-framing is inherent to the encoding
   and documented as such. — `4de6cf2e`
8. **RTC withdraw emitter omitted plen and origin-AS** (`nlri_rtcv4.rs`/`v6`)
   — hand-rolled encoder disagreed with the parser; both Unreach emitters now
   use the shared `emit_rtc_membership`. Was latent (only empty EoR withdraws
   were built). — `031e2c1d`
9. **SR-MPLS Binding SID S/I flags zeroed on re-emit** (`attrs/srpolicy.rs`)
   — a reflector silently turned Specified-BSID-Only / Drop-Upon-Invalid off.
   `BindingSid` now models the flag octet; assigned bits survive the round
   trip, unassigned bits masked both directions per RFC 9830 §2.4.2.
   — `9c528259`
10. **Received NOTIFICATION data always discarded** (`notification.rs`) —
    parse kept the Data octets, RFC 9003 Shutdown Communication decoded and
    rendered (hex fallback otherwise), and `fsm_bgp_notification` now logs
    every received NOTIFICATION with code/subcode/communication. — `cce4f1aa`
11. **COMMUNITIES / LARGE_COMMUNITY width not enforced** (`attrs/com.rs`,
    `attrs/large_com.rs`) — non-zero multiple of 4 (resp. 12) now required
    (RFC 7606 §7.8 / RFC 8092 §3) **and** both types added to the
    treat-as-withdraw set so detection doesn't become a forbidden session
    reset; empty sets no longer emitted. — `4b265a9b`
12. **EVPN MAC/IP lengths validated after octet-rounding** (`nlri_evpn.rs`) —
    `nlri_psize` widened each legal value into a span of eight (41..=48 all
    "valid" MACs). Now exact bit counts (48; 0/32/128) per RFC 7432 §7.2,
    against named constants. — `7537928b`
13. **`many0_complete` silently truncated NLRI lists at 25 sites**
    (`mp_reach.rs`, `mp_unreach.rs`) — a malformed NLRI dropped itself and
    every route after it with no error. All sites replaced by one shared,
    exact-consumption `parse_nlri_block` (`src/parser.rs`); an error now
    reaches the RFC 7606 §3(j) session-reset path, the only outcome the RFC
    permits when the affected routes can't be determined. — `ac309235`
14. **Flow-spec components accepted out-of-order / duplicated**
    (`nlri_flowspec.rs`) — one rule could occupy two BTreeMap precedence keys.
    Order is canonicalised (conjunction ⇒ intent unambiguous; GoBGP does the
    same), duplicate types rejected (genuinely ambiguous). — `da01e5d3`
15. **UPDATE length wrapped by `as u16` on emit** (`update.rs`) — a >65535-byte
    UPDATE emitted a bogus header length, desyncing peer framing. Infallible
    `From` replaced by `try_emit()` / `TryFrom` returning
    `UpdateEmitError::TooLong`; all 27 call sites converted (senders log and
    drop). Attribute-level casts remain → **O3**. — `a8b2d70a`

Post-review, unrelated to a finding: the Graceful Restart capability is now
modeled per RFC 4724 (`1c20a5d7`).

---

## Notes on method

- The original review had no pending diff; it covered the committed crate as
  of 2026-07-16. The 2026-07-17 re-evaluation re-verified every open item
  against `main` at `1c20a5d7` and refreshed all line anchors.
- Memory-safety/panic hunting across the parsers came back clean — the
  residual issues are validation leniency, encode/parse asymmetry, and
  emit-side length casts, not over-reads.
- CONFIRMED findings were checked directly against the source; PLAUSIBLE
  findings have a real mechanism whose trigger depends on peer capability,
  config, or message size.
