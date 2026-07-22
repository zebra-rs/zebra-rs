# isis-packet Audit — Open Findings

**Scope:** `crates/isis-packet/` (plus its call site in
`zebra-rs/src/isis/network.rs`) · nom 8.0.0
**History:** security audit 2026-03-19, revised 2026-04-09 · whole-crate code
review arc 2026-07-18 (15 ranked findings + follow-ups 1–7, PRs #1952–#1996)
**This revision:** 2026-07-21 — `SECURITY_AUDIT.md` is replaced by this file,
every fixed finding dropped, and each surviving item re-verified against `main`
at `57828933`.

Fixed findings are deliberately **not** restated. The security audit's history
lives in the git history of `crates/isis-packet/SECURITY_AUDIT.md`
(`0772cf90..dad8b087`); the code review arc's per-finding detail lives in the
PR descriptions (#1952, #1957, #1961, #1964, #1967, #1969, #1971, #1975, #1977,
#1978, #1983, #1985, #1989, #1994, #1996) and in the git history of
`docs/design/isis-packet-code-review.md`, deleted at `20c81809`.

## Status

**No packet-triggered panic.** Every crash finding from the 2026-03-19 and
2026-04-09 passes is fixed: `is_valid_checksum()` and `checksum_calc()`
length-check before indexing, `ptake`/`ptakev6` validate prefix lengths,
`safe_split_at()` guards every length-driven split on the parse path, all
`From<u8>`/`From<u16>` conversions fall through to `Unknown`, and
`Nsap::from_str` returns `NsapParseError` instead of indexing out of bounds.
`many0_complete` sub-parsers all consume ≥1 byte, so no loop can spin.

**All 15 ranked code-review findings are fixed**, as are follow-up items 1–7.
The emit-side length cluster in particular is largely closed:
`IsisTlvIsNeighbor`, `IsisTlvAreaAddr` and `IsisSubFadExcludeSrlg` cap `len()`
and `emit()` from the same bound, and `emit_sub_tlvs()` now truncates an
over-full block instead of mislabeling it.

**What is left** is one High parser-strictness gap that a real wire can trigger
(**F1**), its Medium sibling (**F2**), three residual local-construction length
desyncs, and two test/validation gaps. Nothing open is a memory-safety issue.

---

## Open findings (ranked, most severe first)

### F1. PDU wire-length fields are parsed but never enforced — CONFIRMED (High)
- **Files:** `src/parser.rs:33` (`length_indicator`), `:329` / `:420` / `:447`
  / `:469` (`pdu_len` on `IsisLsp` / `IsisHello` / `IsisP2pHello` / `IsisCsnp`
  / `IsisPsnp`), `:1525` (`IsisTlv::parse_tlvs`)
- **Category:** correctness / parser differential
- **Bug:** every PDU struct declares `pub pdu_len: u16` and then parses its TLV
  list with `#[nom(Parse = "IsisTlv::parse_tlvs")]`, which is
  `many0_complete(parse_tlv)` — it runs to the end of the **caller's slice**,
  not to the declared length. `length_indicator` is likewise read and never
  used. Neither field bounds anything.
- **Verified empirically** (throwaway probe against the current tree, an L1 LAN
  Hello carrying one Area Address TLV):

  | input | declared `pdu_len` | wire bytes | TLVs parsed | `rest` |
  |---|---|---|---|---|
  | clean | 30 (deliberately wrong) | 33 | 1 | 0 |
  | `+12` zero octets | 30 | 45 | **7** | 0 |
  | `+` one appended Area Address TLV | 30 | 39 | **2** | 0 |

  A wrong `pdu_len` is accepted silently; 12 octets of zero padding become six
  phantom `Unknown(0)` TLVs; an attacker-appended TLV past `pdu_len` is
  accepted as a genuine second area address.
- **Why the wire can hit this:** `zebra-rs/src/isis/network.rs:69` passes the
  whole received frame (`&input[3..]`) to `isis_packet::parse()`. Anything the
  link layer appends past the declared PDU — 802.3 padding to the 60-octet
  minimum on a short PSNP/CSNP, for instance — lands inside the TLV list rather
  than being discarded. Hellos are padded via TLV 8 so they self-frame, but
  nothing in the crate guarantees that for the other PDU types.
- **Impact:** a parser differential against stricter implementations, phantom
  TLVs in the decoded PDU, and — for LSPs — a body that does not correspond to
  the length the checksum and the LSDB were computed over.
- **Fix shape:** split the PDU body at the declared wire length before calling
  `IsisTlv::parse_tlvs()`, and reject a non-empty remainder inside that bounded
  slice. Validate `length_indicator` against `parser::length_indicator(pdu_type)`
  at the same time.

### F2. Length-bounded TLV / sub-TLV parsers silently discard trailing bytes — CONFIRMED (Medium)
- **Files:** `src/parser.rs:1517` (`IsisTlv::parse_tlv`), `src/util.rs:12`
  (`parse_sub_block`), and the value parsers named below
- **Category:** correctness (parser canonicalization)
- **Bug:** the outer parsers slice the declared payload correctly, then throw
  the inner parser's remainder away — `if let Ok((_, val)) = Self::parse_be(tlv,
  tl.typ)` in `parse_tlv`, and `let (_, subs) = many0_complete(parse_one)` in
  `parse_sub_block`. A payload with valid leading data and trailing garbage is
  accepted, and the garbage disappears on re-emit.
- **Still-live examples:**
  - `IsisSubAdminGrp::parse_be` (`src/sub/neigh.rs:450`) — `many0_complete(be_u32)`,
    so a 5-octet payload is one group plus one dropped octet.
  - `IsisTlvMultiTopology::parse_be` (`src/sub/prefix.rs:689`) — accepts an
    odd-length payload and drops the final octet.
  - `IsisTlvP2p3Way::parse_be` (`src/parser.rs:1262`) — parses its optional
    fields by *remaining length*, so 1–3 trailing octets are simply ignored.
- **Why this is cheap to fix now:** finding #10's fix means a TLV whose value
  parse *errors* degrades to `Unknown` (bytes preserved, rest of the PDU still
  parses) instead of truncating the TLV list. Making the length-bounded parsers
  strict therefore no longer risks dropping the remainder of a PDU — the
  degrade path already exists. Require `rest.is_empty()` in `parse_tlv`,
  `parse_sub_block`, and the sub2 block parsers.

### F3. `IsisTlvMultiTopology::len()` wraps at 128 entries — CONFIRMED (low)
- **File:** `src/sub/prefix.rs:706`
- **Category:** robustness (local construction)
- **Bug:** `len()` is `(self.entries.len() * 2) as u8` with no cap while
  `emit()` writes every entry, so a locally-built TLV with ≥128 topologies
  emits a length byte that disagrees with the body — the receiver's TLV walk
  desyncs. This is the last of the four `as u8` sites the 2026-04-09 audit
  named that has not been given the `min()`-in-both-places treatment used by
  `IsisTlvIsNeighbor` (`src/parser.rs:756`), `IsisTlvAreaAddr`
  (`src/parser.rs:682`) and `IsisSubFadExcludeSrlg` (`src/sub/cap.rs:517`).
- **Not reachable from the wire:** parsing bounds the entry count by the TLV's
  own one-octet length, so only a local builder can overflow it.

### F4. `IsisTlvLspEntries::len()` documents its overflow instead of preventing it — CONFIRMED (low)
- **File:** `src/parser.rs:845` (`MAX_ENTRIES` at `:837`)
- **Category:** robustness (local construction)
- **Bug:** `len()` is `(self.entries.len() * 16) as u8`, and the comment states
  the contract outright: *"Callers must keep entries <= MAX_ENTRIES; beyond that
  this u8 wraps while emit() still writes every entry."* The CSNP/PSNP builders
  do shard at 15 entries (finding #1's fix, PR #1952), so the live path is
  safe — but unlike `IsisTlvIsNeighbor`, the emitter does not defend itself, so
  a future builder that forgets the cap silently produces a corrupt TLV.
- **Fix shape:** mirror `IsisTlvIsNeighbor` — `min(MAX_ENTRIES)` in `len()` and
  `take(MAX_ENTRIES)` in `emit()`, keeping the builder-side shard as the policy
  that decides *where* to split.

### F5. `IsisSubAsla::len()` saturates at 255 while `emit()` writes the full body — CONFIRMED (low)
- **File:** `src/sub/neigh.rs:810` (`len`), `:815` (`emit`)
- **Category:** robustness (local construction)
- **Bug:** `len()` computes in `usize` and ends `.min(255) as u8` — correct as
  far as it goes — but `emit()` writes `sabm`, `udabm` and every sub
  unconditionally. An over-full ASLA therefore declares 255 and emits more,
  the exact desync `emit_sub_tlvs()` was fixed to avoid. Saturating the length
  is only half the invariant; the body has to be truncated to match (or the
  build rejected).
- **Severity:** low — 255 octets of ASLA sub-TLVs is not a shape the config
  path can produce today.

### F6. No negative or fuzz coverage for malformed length fields — GAP
- **Category:** test coverage
- **Gap:** the crate has 113 tests and they all pass, but the 2026-04-09
  audit's Priority-3 list is still outstanding: there are no tests for a TLV
  with a valid prefix plus trailing garbage, a PDU carrying TLVs past its
  declared `pdu_len`, or oversized nested sub-TLV emission, and there is no
  `fuzz/` target for `isis_packet::parse()`. F1–F5 should each land with the
  regression test that would have caught them, and a fuzz target over
  `parse()` with malformed length fields is the natural follow-on.

### F7. Live interop validation of the flag/bit fixes — DEFERRED (optional)
- **Category:** validation
- **Gap:** the flag and bit-position fixes from the review arc (RouterCap S/D
  flags, `Srv6TlvFlags` MTID order, admin-group sub-TLV dispatch, ASLA
  SABM/UDABM) are unit-tested against FRR's *source*, not against a running
  neighbor. A BDD or lab run against a real FRR/IOS neighbor exercising the
  RouterCap S-flag, multi-area TLV 1 and MT SRv6 would close the loop the way
  the Cisco IOS interop work did for TLV parsing. This was item 8 of the review
  arc's follow-up list and is the only item from that arc still open.

---

## Cleanup / altitude (open)

- `src/parser.rs` is ~2000 lines carrying the packet header, all five PDU
  bodies, the `IsisTlv` registry and roughly half the TLV codecs. The `sub/`
  split already exists for sub-TLVs; the top-level TLV codecs could follow.
- Everything else the review flagged as non-blocking cleanup has landed:
  `impl_parse_subs!` generates all six sub-TLV registries, `util::parse_sub_block`
  replaced the eight hand-rolled sub-block parses, `pad_to_mtu` deduplicates the
  two Hello padding functions, `bandwidth_sub_tlv!` generates the three RFC 8570
  wrappers, and the seven no-op `is_empty()` methods are gone.

---

## Reviewed and intentionally left as-is

**Type-code tables.** TLV codes, cap/neigh/prefix sub-TLV codes, FAD sub-codes
and the SRv6 endpoint-behavior codepoints all match IANA/RFC and FRR; the
`Behavior` table is pinned by a bidirectional test. `End.M = 74` was verified
against the IANA "SRv6 Endpoint Behaviors" registry
(`draft-ietf-rtgwg-srv6-egress-protection-02`) on 2026-07-18 — the crate is
correct.

**Flag bit positions** checked against FRR and left unchanged: `AdjSidFlags`
(F/B/V/L/S/P), `PrefixSidFlags` (R/N/P/E/V/L), `BindingFlags` (F/M/S/D/A),
`SegmentRoutingCapFlags` (I=0x80 / V=0x40), the SRv6-Capabilities O-flag
(`0x4000`), `MultiTopologyId` LSB-first, and `Restart` RR/RA/SA.

**Width-by-length SID parsing for Binding TLV 149.** Everywhere else the RFC
8667 V/L flags are authoritative (`SidLabelValue::parse_be_flags`, mismatch
degrades to `Unknown`); TLV 149's SID/Label sub-TLV keeps the byte-count parse
because RFC 8667 §2.3 keys the form on the length there.

**`clippy::len_without_is_empty`** is allowed workspace-wide: a TLV `len()` is
a wire length field, not a container length. Do not re-add no-op `is_empty()`
methods. The meaningful all-zero `IsisSysId`/`IsisNeighborId::is_empty` checks
are unrelated and stay.

---

## Invariants to preserve (checklist for new codecs)

1. **Emit derives wire fields from data, not from stored flags** — the S bit,
   prefix length, and Prefix-/Adj-SID V/L flags are all recomputed at emit time
   (the finding-#11 policy). A stored flag that disagrees with the data is a
   bug waiting to be re-emitted.
2. **Lengths compute in `usize` and saturate once at the `u8` boundary** — and
   the body must be bounded by the *same* expression, so a saturated length can
   never disagree with the bytes written (see F3–F5 for the sites that still
   only do half of this).
3. `IsisTlv::wire_len()` is arithmetic — never serialize-to-measure. The LSP
   packer probes the growing TLV through the `SplittableTlv` trait; keep
   `value_wire_len()` unsaturated so the splitter sees the true size.
4. **New sub-TLV registries use `impl_parse_subs!`** (`sub/mod.rs`) and
   `util::parse_sub_block` — degrade-to-`Unknown` comes free. Do not hand-roll
   a seventh copy.
5. Guard every length-driven split with `packet_utils::safe_split_at()`;
   validate prefix lengths through `ptake`/`ptakev6` before slicing.
6. A malformed value degrades to `Unknown` with its bytes preserved rather than
   truncating the TLV list — parse errors must not cost the rest of the PDU.

---

## Verification

```sh
cargo test -p isis-packet
```

113 tests, all passing as of `57828933`. F1's table above came from a
throwaway integration test run against this tree and then removed; the
permanent version belongs with F1's fix (see F6).
