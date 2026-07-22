# ospf-packet Audit — Open Findings

**Scope:** `crates/ospf-packet/` (OSPFv2 + OSPFv3 parse & emit), plus its
consumers in `zebra-rs/src/ospf/`
**History:** security audit (buffer-overrun / crash sweep) · whole-crate code
review 2026-07-17, re-verified 2026-07-21 (15 findings, PRs #1959–#2010, #2042)
**This revision:** 2026-07-21 — `crates/ospf-packet/SECURITY_AUDIT.md` and
`docs/design/ospf-packet-code-review.md` are merged here, every fixed finding
dropped, and each surviving item re-verified against `main` at `57828933`.

Fixed findings are deliberately **not** restated. The security audit's history
lives in the git history of `crates/ospf-packet/SECURITY_AUDIT.md`; the code
review's per-finding analysis lives in the git history of
`docs/design/ospf-packet-code-review.md` and in the PRs that closed each one
(#1959, #1963, #1966, #1970, #1974, #1979, #1982, #1986, #1990, #1993, #1998,
#2005, #2010, #2042).

## Status

**No packet-triggered panic, and no unvalidated wire-driven allocation.** The
three remote-DoS parse bugs are fixed: the Extended-Prefix TLV rejects
`prefix_len > 32`, the SRv6 Locator TLV bounds its copy to 16 octets, and all
four `Vec::with_capacity`-from-wire-count sites go through
`packet_utils::bounded_capacity`. `validate_checksum()` length-checks before
slicing, and `lsa_checksum_calc` now delegates to
`packet_utils::fletcher_lsa_checksum`, which returns 0 for short input instead
of underflowing.

**All four silent interop wire-format bugs are fixed** — the RFC 7166 AT
Options bit, `PrefixSidFlags` bit positions, the RFC 8666 Adj-SID weight
offset, and the RFC 9513 End.X SID header width — each with a byte-offset unit
test, and BDD coverage where a `show` could discriminate the bug.

**What is left** is one confirmed emit-side integer overflow (**F1**), two
interop/layout items that were never validated against a foreign
implementation (**F2**, **F3**), and three low-severity robustness and
test-hygiene items. Nothing open is a memory-safety issue or a live remote DoS.

---

## Open findings (ranked, most severe first)

### F1. `lsa_len()` computes LSA lengths in `u16` and wraps — CONFIRMED
- **File:** `src/parser.rs:821`, `:864`, `:889`, `:929`, `:991`, `:1012`
  (plus the three `tlvs.iter().map(wire_len).sum()` roll-ups at `:1229`,
  `:1703`, `:1812`)
- **Category:** correctness (emit-side integer overflow)
- **Bug:** every v2 `lsa_len()` multiplies a `Vec::len()` by a constant and adds
  a base, all in `u16`, with no checked arithmetic:

  | site | expression | wraps when |
  |---|---|---|
  | `:821` `RouterLsa` | `4 + links.iter().map(\|l\| l.lsa_len()).sum::<u16>()` | summed link size > 65531 |
  | `:864` `OspfRouterLink` | `12 + toses.len() as u16 * 4` | `toses.len() >= 16381` |
  | `:889` `NetworkLsa` | `4 + attached_routers.len() as u16 * 4` | `>= 16383` |
  | `:929` `SummaryLsa` | `8 + tos_routes.len() as u16 * 4` | `>= 16382` |
  | `:991` / `:1012` `AsExternalLsa` / `NssaLsa` | `16 + tos_list.len() as u16 * 12` | `>= 5460` |

  A wrapped `lsa_len()` produces an LSA header length far smaller than the body
  that follows, so a peer's TLV/LSA walk desynchronizes for the rest of the
  update.
- **Reachability, stated honestly:** the *parse* side can build vectors this
  large — the element counts are bounded only by the enclosing LSA length, and
  an LSA may declare up to 65535 octets — but a received LSA is re-flooded from
  its cached `raw` bytes (finding #10's fix, #1993), not from a typed re-emit,
  so the wrap does not currently reach the wire on the forwarding path. The live
  exposure is a **locally originated** LSA, which today is bounded by config
  size. That makes this latent rather than exploitable — but it is the last
  unchecked length arithmetic in the crate, and every other emitter in the
  workspace has been converted (`isis-packet` sub-TLVs, the v2/v3 packet length
  stamp in #2042).
- **Fix shape:** compute in `usize`, saturate once at the `u16` boundary, and
  bound the emitted body by the same expression — the invariant already applied
  to `Ospfv2Packet::emit` / `Ospfv3Packet::emit` in #2042, and to
  `IsisTlvIsNeighbor` / `IsisTlvAreaAddr` in isis-packet.

### F2. `Ospfv3IntraAreaPrefixTlv` layout never interop-validated — OPEN (RFC 8362 §3.9)
- **File:** `src/v3.rs:1941`
- **Category:** interop
- **Gap:** the E-Intra-Area-Prefix TLV uses a 16-bit metric plus an embedded
  referenced-LSA triple (`referenced_ls_type` as a `u32` carrying the 16-bit LS
  Type in its lower half, `referenced_link_state_id`,
  `referenced_advertising_router`). The layout is documented in the struct's
  comment and zebra-to-zebra round-trips pass, but it has never been checked
  against another implementation — and FRR does not implement the OSPFv3
  Extended-LSA / SRv6 sub-TLVs, so there is no easy reference peer.
- **Why it matters:** this is the same shape as findings 4–7, all of which were
  silent wire-format errors that zebra-to-zebra round-trips could not detect
  precisely because emit and parse agreed with each other. A field-by-field
  read against RFC 8362 §3.9 is the cheap check; a packet capture from any
  other implementation is the real one.

### F3. Non-bijective `From<u8>` for link types — OPEN (low)
- **Files:** `src/parser.rs:754` (`OspfLinkType`, unknown → `Stub`),
  `src/v3.rs:705` (`Ospfv3RouterLinkType`, unknown → `PointToPoint`)
- **Category:** correctness (cosmetic)
- **Bug:** every unrecognized link-type octet collapses onto a valid variant, so
  the parsed value silently misrepresents the wire and a typed re-emit changes
  a checksummed byte.
- **Severity dropped since the review:** the consequence that mattered — a
  `verify_checksum` false-reject — is gone since #1993 verifies received LSAs
  over the cached `raw` bytes. (The crate's own
  `verify_checksum_uses_raw_lsa_bytes` test pins exactly this case, using wire
  link type 255 decoded as `Stub`.) What remains is that a `show` renders a
  link type the sender never sent. An `Unknown(u8)` variant would fix it.

### F4. Unbounded copy of an untrusted LSA payload length — OPEN (low)
- **File:** `src/parser.rs:702`
- **Category:** robustness
- **Bug:** `payload_length = total_length.saturating_sub(20)` comes from the LSA
  header, and an unparseable body is copied wholesale into
  `UnknownLsa { data: payload_input.to_vec() }`.
- **Severity, stated honestly:** `take()` fails unless the bytes are actually
  present, so the allocation is bounded by the datagram the attacker already
  sent — there is no amplification, and a 65535-octet LSA is the ceiling. This
  is a "cap it to something sane" hardening item, not a live memory-exhaustion
  vector. Listed because the audit raised it and the cap was never added.

### F5. Two `#[ignore]`d tests are broken, not slow — CONFIRMED (test hygiene)
- **File:** `tests/ospfv2.rs:228` (`parse_ls_summary`), `:243` (`parse_lsa_type7`)
- **Category:** test coverage
- **Bug:** both are `#[ignore]`d, and running them (`cargo test -p ospf-packet
  --test ospfv2 -- --ignored`) fails: each feeds a bare LSA into `parse()`,
  which expects a full 24-octet OSPF packet header, so the `.unwrap()` panics.
  They are mis-written against the wrong entry point rather than disabled for
  cost. `parse_lsa_type7` is a stale duplicate of `parse_unknown2` (`:258`),
  which uses the *identical* bytes, calls `UnknownLsa::parse_be`, and passes.
- **Also:** neither ignored test asserts anything beyond `rem.is_empty()` — the
  bodies are `println!`. Either point them at the right entry point and give
  them real assertions, or delete them; leaving them `#[ignore]`d reads as
  "known-slow" and hides that they are simply wrong.

### F6. No fuzz target over `parse` / `parse_v3` — GAP
- **Category:** test coverage
- **Gap:** there is no `fuzz/` directory. The crate has 102 passing tests and
  the panic findings were all found by review rather than by fuzzing; a fuzz
  target over the two public parse entry points with malformed length fields
  would be the natural backstop, especially for the TLV/sub-TLV recursion in
  `v3.rs`.

---

## Cleanup / altitude (open)

- `src/parser.rs` (~2900 lines) and `src/v3.rs` (~3400 lines) each carry the
  packet header, every LSA body, and the whole TLV/sub-TLV registry for their
  version. The shared payload codecs have already been hoisted to
  `packet-utils` (`fletcher_lsa_checksum`, `SidLabelTlv`, `FadFlags`, `FadSrlg`,
  `ExtAdminGroup`, `bounded_capacity`) — what remains is a per-version file
  split, not further deduplication.
- `Ospfv2Packet::emit` stamps the packet length as `buf.len()` and writes it to
  `buf[2..4]`, which silently assumes the caller passed an empty buffer. The
  contract holds at every current call site but is not stated or asserted.

---

## Reviewed and intentionally left as-is

**`OspfLsa::verify_checksum` buffer indexing** (`src/parser.rs:575`). The
`buf.len() < 18` guard makes `buf[16]` / `buf[17]` safe, and the function now
prefers the cached `raw` wire bytes over a typed re-emit (#1993). The audit
called the index-after-guard pattern fragile; it is correct as written and the
guard is directly above the indexing, so no change.

**`Ospfv2Packet::emit` checksum range** (`src/parser.rs:108`). `buf[12..14]`
and the `buf[..16]` / `buf[24..]` checksum spans assume ≥24 octets, which the
24-octet OSPFv2 header guarantees before any payload arm runs. The overflow
direction — a packet exceeding the 16-bit length field — is covered by the
`debug_assert` + release clamp added in #2042.

**Findings 6 and 7 have no BDD coverage, deliberately.** The daemon originates
the Adj-SID weight and End.X SID fields as zero, so a zebra-to-zebra `show`
renders identically under either the old or the fixed layout. The byte-offset
unit tests are the meaningful lock; a BDD would pass under the bug.

---

## Invariants to preserve (checklist for new codecs)

1. **Lengths compute in `usize` and saturate once at the `u16`/`u8` boundary** —
   and the emitted body must be bounded by the *same* expression, so a
   saturated length can never disagree with the bytes written. F1 is the last
   site that does not do this.
2. **Counts are derived at emit, never stored** — `num_adv` / `num_links` come
   from `.len()` (#1986). A stored counter is a bug waiting for a mutate path
   that forgets to re-sync it.
3. **Received LSAs verify and re-flood over cached `raw` bytes**, not a typed
   re-emit — the typed form may reorder or drop unmodeled sub-TLVs (#1993).
   `update()` invalidates `raw` because it only runs on the self-originated
   path.
4. **Distinguish "unknown LS type" from "known type, body failed to parse"** —
   the first degrades to `Unknown`, the second propagates an error (#1990). A
   blanket catch-all re-floods corruption through the area.
5. **Pre-allocate through `packet_utils::bounded_capacity`**, never
   `Vec::with_capacity(n)` with `n` straight off the wire.
6. **Bound every fixed-size copy by the array, not by the wire count** — a
   wire-derived byte count (`prefix_len`, `locator_length`) must be validated or
   clamped before it indexes a `[u8; N]`.
7. **Wire-format changes need a byte-offset unit test.** A zebra-to-zebra
   round-trip cannot detect a layout error, because emit and parse agree with
   each other — that is precisely how findings 4–7 survived. F2 is the
   outstanding case.

---

## Verification

```sh
cargo test -p ospf-packet
```

102 tests pass as of `57828933` (85 unit + 17 integration); 2 further tests are
`#[ignore]`d and fail when run — see **F5**.
