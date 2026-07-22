# bgp-packet Audit — Open Findings

**Scope:** `crates/bgp-packet/` (plus its consumers in `zebra-rs/src/bgp/`) ·
nom 7.1.3
**History:** security audit 2026-04-09, re-audited 2026-06-26 / 2026-06-27 /
2026-07-17 · whole-crate code review 2026-07-16, re-ranked 2026-07-17
**This revision:** 2026-07-21 — the separate `SECURITY_AUDIT.md` and
`CODE_REVIEW_FINDINGS.md` are merged here, every fixed finding dropped, and
each surviving item re-verified against `main` at `bbda8a44`.

Fixed findings are deliberately **not** restated. The full analysis of each one
lives in the git history of the two source documents
(`ed5495bd..98ab80f2`) and in the commits they reference.

## Status

**Security: no open findings.** Every panic / DoS / memory-safety finding from
every audit pass is fixed and pinned by a regression test (`cargo test -p
bgp-packet`). The parse paths are hardened: every length-prefixed slice is
bounded with `packet_utils::safe_split_at()`, every TLV loop makes ≥1 byte of
progress, no attacker-sized allocation exists, and no
`unwrap`/`expect`/`unreachable!` is reachable from wire bytes.

**What is left** is validation leniency, encode/parse asymmetry, latent
emit-side length casts, and two deferred interop features. Exactly one open
item (**F1**) lets a *conformant* peer message tear a session down.

Two items that the 2026-07-17 review still listed as open have since been
fixed and are gone from this list:

- `MupRoute::parse` full-consumption (was O5) — every route-type arm now
  rejects leftover bytes inside its `take(length)` body (`98ab80f2`; tests
  `{isd,dsd,t1st,t2st}_rejects_padded_length`).
- `as4` driven from capability negotiation, AS4_PATH / AS4_AGGREGATOR and the
  RFC 6793 §4.2.3 merge (was O1) — implemented in `1641a59e`;
  `peer_packet_parse` now passes `opt.is_as4()`.

---

## Open findings (ranked, most severe first)

### F1. MP next-hop framing drift — EVPN/RTC/BGP-LS reject the 32-octet form — CONFIRMED
- **File:** `src/attrs/mp_reach.rs:413` (EVPN), `:471` (RTCv4), `:512`
  (RTCv6), `:568` (BGP-LS)
- **Category:** correctness / interop
- **Bug:** The per-AFI/SAFI next-hop framing (`match nhop_len { 4/16/32 }`) is
  copy-pasted ~10 times through `parse_nlri_opt`, and the copies have drifted:
  the IPv6-unicast, labeled-unicast, MUP and SR-Policy arms accept the RFC 2545
  32-octet next hop (global + link-local), while the EVPN, RTCv4, RTCv6 and
  BGP-LS arms hard-reject anything but 4/16.
- **Failure scenario:** A peer that includes the link-local next hop on one of
  the rejecting AFI/SAFIs (RFC 2545 §3 explicitly defines the 32-octet form;
  implementations emit it whenever a link-local is present) fails the MP_REACH
  parse. MP_REACH is deliberately *not* in the treat-as-withdraw set
  (RFC 7606 §3(j)), so the error propagates as a **session reset** — and recurs
  on every retry, wedging the session.
- **Fix shape:** one shared next-hop-framing helper beside `parse_nlri_block`
  in `src/parser.rs`; that removes both the defect and the duplication.

### F2. Attribute-level emit length casts — `len as u16` / `len as u8` with no clamp — LATENT
- **Files:** `src/attrs/mp_reach.rs:858` (+7 more), `src/attrs/mp_unreach.rs`
  (8 sites), `src/attrs/nlri_bgpls.rs:184,316,494,675`,
  `src/attrs/bgpls_attr.rs:156`, `src/attrs/nlri_evpn.rs:1153-1377` (per-route
  length octet), `src/attrs/nlri_mup.rs:679` (`as u8`),
  `src/attrs/prefix_sid.rs:406`, `src/attrs/srpolicy.rs:595-597`
- **Category:** robustness
- **Bug:** The UPDATE-level wrap was fixed (`UpdatePacket::try_emit`,
  `UpdateEmitError::TooLong`, `a8b2d70a`), but the attribute-level casts remain:
  each emit helper writes its value length with a bare cast and no cap, so an
  over-long attribute body would wrap the length field.
- **Why still open:** fixing these means making the `AttrEmitter` trait
  fallible, which cascades through every attribute emitter. Bounded in practice
  by the callers' chunking — `pop_ipv4`/`pop_ipv4_mp_reach` bound `buf.len()`
  to `max_packet_size` ≤ 65535 and are safe by construction — so latent, not
  live. This refactor is also the natural moment to collapse the ~16
  copy-pasted MP attribute trailers (see cleanup below): same trait change,
  same files.

### F3. Real RFC 5701 IPv6-extended-community support — DEFERRED FEATURE
- **Files:** `src/attrs/attr.rs:33-45` (invariant comment),
  `src/attrs/ext_ipv6_com.rs`
- **Category:** feature / interop
- **Current state (correct, minimal):** code 25 is deliberately *unnamed* in
  `AttrType`, so it decodes as `Unknown(25)` and takes the RFC 4271 §9
  optional-transitive path — retained with the Partial bit and propagated. The
  `ext_ipv6_com` module is a correct but unwired skeleton (endian, display and
  panic bugs already fixed) and is unreachable from the wire.
- **What full support needs:** an `Attr::ExtendedIpv6Com` variant, a `BgpAttr`
  field, an `AttrEmitter`, and RT matching against IPv6 route-targets. Matters
  once IPv6-address-specific route targets are used for VPN import/export.
- **Invariant to keep:** every code named in `AttrType` must have a matching
  `Attr` variant — a half-recognized code skips the §9 unknown-attribute path
  and becomes a session reset (that was the live bug here, fixed in
  `e97589e1`).

### F4. RTC mixed exact + default/partial membership filtered to the exact RT — KNOWN GAP
- **File:** `src/attrs/nlri_rtcv4.rs:59` (`is_exact`) · consumers
  `zebra-rs/src/bgp/route.rs:6919,6930`
- **Category:** correctness (documented limitation)
- **Gap:** a peer mixing an exact RT with a default (`plen=0`) or partial
  membership is still filtered to the exact one, because "wants everything" has
  no representation distinct from "said nothing" — only `is_exact()` RTs enter
  `peer.rtcv4`. Expressing it needs a flag threaded through all seven filter
  sites. No known implementation sends that combination, and the failure
  direction is over-advertising (safe for RTC), so this stays low.

### F5. Flow-spec traffic-rate decoded as raw `f32` with no finite check — PLAUSIBLE
- **File:** `src/attrs/flowspec_action.rs:71,75`
- **Category:** robustness
- **Bug:** `as_flowspec_action` builds `TrafficRateBytes`/`TrafficRatePackets`
  from attacker-controlled bytes with `f32::from_be_bytes` and no `is_finite()`
  check; NaN/Inf rates decode as valid.
- **Severity:** the type is documented as interpretation-only ("f32 rates are
  not `Eq`/`Ord`"), so the original dedup/compare concern is designed away. The
  residual risk is a NaN/Inf rate reaching a future policer consumer; clamp or
  reject at decode when one is wired.

### F6. SR Policy Weight sub-TLV accepts `weight = 0` — CONFIRMED (low)
- **File:** `src/attrs/srpolicy.rs:461`
- **Category:** robustness
- **Bug:** `parse_weight` validates only the 6-octet length; RFC 9256 makes a
  zero weight invalid, and a `share = weight / total` consumer can divide by
  zero when all segment-list weights are 0.

### F7. SRv6 service sub-TLV interleaving not preserved on re-emit — CONFIRMED (low)
- **File:** `src/attrs/prefix_sid.rs:295` (decode), `:410` (emit)
- **Category:** robustness
- **Bug:** `decode_srv6_service` splits SID-information sub-TLVs and unknown
  sub-TLVs into separate vecs, and `emit_srv6_service` writes all SIDs first,
  so an input interleaving unknown sub-TLVs between SIDs re-emits in a
  different order — despite the module's bit-exact-round-trip claim. TLV order
  is not semantically significant per RFC 9252, and no known sender
  interleaves, so low.

### F8. ROUTE_REFRESH parse skips length / trailing-byte validation — CONFIRMED (low)
- **File:** `src/route_refresh.rs:35`
- **Category:** robustness
- **Bug:** `parse_packet` is a bare `parse_be` — it neither validates
  `header.length == 23` nor rejects trailing in-message bytes, so a
  ROUTE_REFRESH with a padded body parses as if well-formed (RFC 7313 §6 wants
  it treated as malformed).

### F9. `peek_bgp_length` returns unvalidated lengths — LATENT (low)
- **File:** `src/parser.rs:95`
- **Category:** robustness
- **Bug:** returns `Some(length)` without validating `>= 19` / `<= 4096`; the
  sole current caller re-checks, so this is only a trap for a future caller.

---

## Cleanup / altitude (open)

- **Next-hop framing duplication** is **F1** — the drift between the ~10 copies
  is a ranked interop defect, not just cleanup; the dedup is the fix.
- `RouteDistinguisher` has a centralized `parse_be` but still no `emit`; its
  wire encoding is hand-rolled at ~22 sites across 5 files — `nlri_evpn.rs`
  (12), `nlri_mup.rs` (4), `nlri_vpnv4.rs`/`nlri_vpnv6.rs` (3 each). The two
  halves of the codec live at different altitudes.
- The MP_REACH/MP_UNREACH attribute trailer (buffer value → compute extended
  flag → put flags/type/len/value) is copy-pasted 16 times (8 per file).
  `AttrEmitter::attr_emit` already does it. A missed copy silently emits a
  malformed attribute for one SAFI. Fold into the F2 fallible-emitter refactor
  — same trait, same files.
- The labeled/VPN prefix parse body (plen floor check, 3-byte label,
  `plen -= hdr`, `psize` guards, copy into `[0u8;N]`) is copy-pasted ~9 times
  across `nlri_labeled_unicast.rs`, `nlri_vpnv4.rs`, `nlri_vpnv6.rs`,
  `nlri_ipv4.rs`, `nlri_ipv6.rs`, `nlri_mup.rs`; add shared
  `parse_v4_prefix`/`parse_v6_prefix` beside `parse_nlri_block`.
- `src/update.rs` — `pop_evpn`/`pop_srpolicy`/`pop_srpolicy_withdraw`/
  `pop_vpnv6`/`pop_vpnv4` still repeat the same ~25-line UPDATE framing
  scaffold.
- `src/util.rs` `u32_u24` duplicates `packet_utils::u32_u8_3`;
  `src/parse_be.rs` re-declares `packet-utils`' `ParseBe` trait + `Ipv4Addr`
  impl; `prefix_sid.rs` `parse_be_u24`/`put_be_u24` re-implement
  `nom::number::complete::be_u24` / `crate::u32_u24`.

---

## Reviewed and intentionally left as-is

**MP_REACH Reserved/SNPA octet** (`src/attrs/mp_reach.rs:238` and each arm).
The octet is read, modeled per-variant (`snpa: u8`) and preserved on re-emit —
per RFC 4760 it is a Reserved octet that MUST be 0 and is ignored on receipt,
which this satisfies. Residual quibbles only: a pre-RFC-4760 (RFC 2858) peer
sending a nonzero SNPA *list* would misframe the NLRI — now surfaced loudly by
the strict `parse_nlri_block` rather than silently misparsed — and re-emitting
a preserved nonzero octet technically violates the transmission MUST. No action
planned unless an RFC 2858 peer materialises.

**MP_REACH Flowspec `nhop_len`.** VPNv4 accepts only 12/24/48, VPNv6 only
24/48; EVPN/RTC/Link-State require 4 or 16 (see F1). The Flowspec arm
intentionally `take()`s whatever `nhop_len` says — length-safe (bounded by the
buffer), just not value-restricted.

**`payload.len() as u8` sites where a clamp would desync length from body:**

- *Fixed-size EVPN bodies* (11 emitters in `nlri_evpn.rs`): worst case ≈79
  octets (IgmpLeaveSync with IPv6 addresses) — far below 256, the cast cannot
  truncate.
- *Variable opaque bodies* (EVPN LeafAd `route_key`, MUP `Unknown` body,
  `tunnel_encap`/`srpolicy` TLV values with type < 128): bounded ≤255 on the
  parse path by the enclosing 1-octet length, so parse-then-re-emit never
  truncates; an oversized locally-built object is simply unencodable.
- *AS_PATH segment count* (`aspath.rs:177`): segments split at 255 via
  `chunks(AS_SEGMENT_MAX)`.

All other production `len as u8` sites sit behind an extended-length / u16
fallback (attribute emitter, vpnv4/v6, flowspec <240 rule, mp_reach/unreach,
RFC 9072 OPEN extension).

---

## Invariants to preserve (checklist for new parsers/emitters)

1. Bound every length-prefixed slice with `packet_utils::safe_split_at()`;
   never raw `split_at()` / direct indexing on wire input.
2. After parsing inside a bounded slice, reject a non-empty remainder
   (`ErrorKind::LengthValue`) — treat-as-withdraw semantics, no silent drops.
3. Validate prefix/address length octets against their family maximum before
   `nlri_psize()`; check buffer length before every fixed-width copy.
4. Fixed-width repeating attributes: reject payloads that are empty or not a
   multiple of the element size.
5. Emitters: derive `len()` and the emitted bytes from one shared clamp/count
   helper; a 1-octet length field needs either a proof the body can't reach 256
   or a clamp that keeps length and body in sync.
6. Every attribute code named in `AttrType` must have a matching `Attr`
   variant — a half-recognized code skips the RFC 4271 §9 unknown-attribute
   path and becomes a session reset.

---

## Notes on method

- Findings marked CONFIRMED were checked directly against the source;
  PLAUSIBLE findings have a real mechanism whose trigger depends on peer
  capability, config, or message size.
- Memory-safety/panic hunting across the parsers has come back clean on every
  pass since 2026-06-26 — the residual issues are validation leniency,
  encode/parse asymmetry, and emit-side length casts, not over-reads.
- Line anchors are current as of `bbda8a44`; re-verify them before quoting a
  finding in a commit message.
