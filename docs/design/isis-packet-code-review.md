# `crates/isis-packet/` — Code Review

**Scope:** the entire `crates/isis-packet/` crate (~10k lines of IS-IS wire-format
parser/serializer).
**Method:** 10 independent finder angles (line-by-line, parse↔emit round-trip,
length/bounds, Rust pitfalls, sub-TLV dispatch, reuse/simplification/efficiency,
altitude, conventions, SRv6 deep-dive) plus a full manual read, with the top
findings verified against the actual daemon callers in `zebra-rs/src/isis/` and
against the FRR reference implementation (`../frr/isisd`).

## Overall assessment

The **parse path is genuinely well-defended**: every length-driven slice goes
through `packet_utils::safe_split_at`, `ptake`/`ptakev6` bound-check prefix
lengths before slicing, the `be_uNN` combinators are range-safe, and the
top-level TLV loop (`parser.rs:1356-1370`) degrades a malformed *known* TLV to
`Unknown` so one bad TLV can't abort the whole PDU. As a result there are
essentially **no wire-triggered panics** in the TLV/sub-TLV parsers.

The real defects cluster in two places:

1. **Emit-side length fields that disagree with the bytes written** — `len()`
   returns a `u8` computed with truncating `as u8` casts or panicking `.sum()`,
   while `emit()` writes the untruncated data. On the wire this desyncs the
   receiver's TLV loop; in debug builds it can panic.
2. **A few flag bit-layouts and codepoints** that don't match the RFC / FRR.

All flag-position and codepoint questions below were resolved against the FRR
source, not left as guesses.

---

## Findings (ranked, most severe first)

Severity legend: 🔴 high · 🟠 medium · 🟡 low. Verdict: **CONFIRMED** (inputs +
wrong output identified) · **PLAUSIBLE** (mechanism real, trigger conditional).

### 1. 🔴 `IsisTlvLspEntries::len()` wraps at ≥16 entries → corrupt CSNP/PSNP — CONFIRMED — ✅ FIXED (PR #1952)
`crates/isis-packet/src/parser.rs:755`

`len()` is `(self.entries.len() * 16) as u8`, which wraps mod-256, but `emit()`
writes every entry. The daemon's SNP builders size a single `LspEntries` TLV by
the **MTU budget**, not the 255-byte TLV limit:

- `csnp_generate` — `zebra-rs/src/isis/lsp.rs:1649`: `entry_size_max = available_len / 16`
- PSNP builder — `zebra-rs/src/isis/flood.rs:260`: same `available_len / 16`

For a 1500-byte MTU that is ~92 entries per TLV, but the one-byte length field
can only express 15 entries (`15 * 16 = 240 ≤ 255`).

**Failure:** an LSDB with 16 LSPs emits length byte `0` (`16*16 = 256`) followed
by 256 bytes of entries. A conformant receiver (including this crate's own
parser) reads 0 value bytes, then interprets the first entry's bytes as the next
TLV header — the whole CSNP/PSNP desyncs and **LSDB synchronization breaks on any
network with more than 15 LSPs per level**. Small BDD topologies stay under 16
LSPs, which is why it has not surfaced in testing.

**Fixed in PR #1952:** added `IsisTlvLspEntries::MAX_ENTRIES` (15) and capped
`entry_size_max` in both `csnp_generate` and the PSNP builder, so larger LSDBs
span more SNP PDUs. Unit tests pin the exact-length round-trip at 15 entries and
the mod-256 wrap beyond it; BDD scenario `isis_csnp_large_lsdb` drives a >15-LSP
LSDB through DIS CSNP sync.

### 2. 🔴 `RouterCapFlags` S/D flags at the wrong bit positions — CONFIRMED — ✅ FIXED
`crates/isis-packet/src/sub/cap.rs:214`

```rust
#[bitfield(u8, debug = true)]
pub struct RouterCapFlags {
    #[bits(6)] pub resvd: u8,   // bits 0-5
    pub d_flag: bool,           // bit 6 → 0x40
    pub s_flag: bool,           // bit 7 → 0x80
}
```

RFC 4971/7981 put **S at `0x01`, D at `0x02`** with the reserved bits in the MSBs.
Confirmed against FRR: `../frr/isisd/isis_tlvs.h:188` `ISIS_ROUTER_CAP_FLAG_S 0x01`,
`:189` `ISIS_ROUTER_CAP_FLAG_D 0x02`.

**Failure:** a TLV 242 from FRR/Cisco with `S=0x01` (flood across the entire
domain) parses as `s_flag()=false`; zebra setting `s_flag` emits `0x80`, which a
conformant receiver reads as reserved and treats a domain-wide capability as
area-local. `flags_serde.rs` and `cap_disp.rs` expose the same wrong bits.

Note the sibling `SegmentRoutingCapFlags` (I=`0x80`/V=`0x40`) *is* correct and
matches FRR (`ISIS_SUBTLV_SRGB_FLAG_I 0x80` / `_V 0x40`) — RouterCap simply
copied the MSB-aligned convention when it needed the LSB-aligned one.

**Fixed:** `s_flag` and `d_flag` are now declared first (LSB-first) with
`resvd(6)` last, so S=`0x01`, D=`0x02`; a unit test pins both bit positions in
each direction. `flags_serde.rs` and `cap_disp.rs` go through the accessors, so
they were corrected by the same change.

### 3. 🔴 `Nsap::from_str` panics (index OOB) on a malformed `net` — CONFIRMED — ✅ FIXED
`crates/isis-packet/src/nsap.rs:116` (also `:122`, `:127`)

The three system-id groups are decoded assuming each is 4 hex chars (2 bytes) and
then indexed at `[0]` and `[1]`, but the earlier validation
(`nsap.rs:100-104`) accepts *any* group of length 2 **or** 4.

**Failure:** `Nsap::from_str("49.0000.0000.00.0000.00")` passes the length check;
a system-id-position part `"00"` `hex::decode`s to a single byte, and
`sys_id.id[..] = sys_id_val[1]` panics (`index out of bounds: len is 1 but index
is 1`). Reached from operator config via `.parse::<Nsap>()` in
`zebra-rs/src/isis/config.rs` — a malformed `net` value **crashes the IS-IS
daemon**.

**Fixed:** a `sys_id_pair` helper `hex::decode`s each system-id group and
`try_into`s it to `[u8; 2]`, returning `NsapParseError` on any other length; a
unit test covers a 2-char group in each of the three system-id positions.

### 4. 🟠 `IsisTlvIsNeighbor::len()` wraps at ≥43 neighbors — CONFIRMED — ✅ FIXED
`crates/isis-packet/src/parser.rs:682`

`len()` is `(self.neighbors.len() * 6) as u8` with no cap; `emit()` writes every
neighbor. TLV 6 is built from all adjacencies in `zebra-rs/src/isis/ifsm.rs:173`.

**Failure:** a LAN IIH advertising 43 neighbors: `len()` = `43*6 = 258 as u8 = 2`,
`emit()` writes 258 bytes. The receiver reads 2 bytes and re-enters TLV parsing
256 bytes early, reading neighbor MAC bytes as TLV headers; the Hello's following
TLVs (Auth, Protocols Supported) are lost and adjacencies flap on a large LAN.

**Fixed:** both — `IsisTlvIsNeighbor::MAX_NEIGHBORS` (42) caps `len()` and
`emit()` consistently, and the Hello builder shards larger adjacency sets
across multiple TLV 6 instances so no neighbor is dropped. The receive path's
`has_mac` now ORs across instances (it previously let a later instance clobber
a match from an earlier one). Unit test pins the 43-neighbor truncation.

### 5. 🟠 `Srv6TlvFlags` MTID bitfield declared in inverted order — CONFIRMED — ✅ FIXED
`crates/isis-packet/src/sub/prefix.rs:1090`

The 2-octet header of the SRv6 Locator TLV (type 27) is **4 reserved MSBs +
12-bit MTID** (RFC 9352 §7.1). The struct declares `resvd(4)` first, so it lands
at LSB bits 0-3 and the 12-bit field at bits 4-15 — the *exact* inverted-order
bug already found and fixed for `MultiTopologyId` (see the explanatory comment at
`prefix.rs:621-631`), left unfixed here. It also models the MTID as an unnamed
`v_flag` and never surfaces the topology id.

**Failure:** an SRv6 Locator TLV under MT 2 arrives as `0x0002`; `v_flag()`
(bits 4-15) reads 0 and `resvd` reads 2, so MT-2 locators can't be distinguished
from MT-0, and a locally-built MTID=2 emits `0x0020`, which a peer reads as MTID
32. MTID=0 (single-topology SRv6) round-trips by luck, so this only breaks
multi-topology SRv6. FRR carries an explicit `uint16_t mtid` for this TLV.

**Fixed:** the layout now mirrors `MultiTopologyId` — the 12-bit `mtid` is
declared first, `resvd(4)` second — and the field is named `mtid` (also in the
serde helper). A unit test pins wire `0x0002` ⇄ MT 2 and the reserved top
nibble, plus a full `IsisTlvSrv6` round-trip.

### 6. 🟠 `IsisTlvAreaAddr::parse_be` drops all but the first area address — CONFIRMED — ✅ FIXED
`crates/isis-packet/src/parser.rs:649`

The Area Address TLV (type 1) value is a sequence of `{length, area}` pairs, but
`parse_be` reads exactly one pair and returns; `parse_tlv`'s
`if let Ok((_, val))` discards the unconsumed remainder. `maxAreaAddresses` is up
to 3.

**Failure:** a router packing two areas into one TLV 1
(`[03,49,00,01, 03,49,00,02]`) has its second area silently dropped, so L1 area
matching against a multi-area neighbor fails and adjacencies that should form on
the secondary area are rejected. `emit()` is symmetric-single, so zebra→zebra
round-trips hide it — only *received* multi-area TLVs lose data.

**Fixed:** the field is now `area_addrs: Vec<Vec<u8>>`; parse loops over every
`{length, area}` pair and emit writes each one back (len/emit truncate
consistently at the 255-byte TLV budget). The daemon's L1 area gate
(`l1_area_compatible`) matches against *any* advertised area. Unit test pins
the two-area round-trip.

### 7. 🟠 Per-entry sub-TLV length uses panicking/wrapping `u8` arithmetic — CONFIRMED — ✅ FIXED
`crates/isis-packet/src/sub/neigh.rs:176` (and siblings)

`IsisTlvExtIsReachEntry::sub_len()` is `.map(|s| s.len()+2).sum::<u8>()` and
`len()` is `11 + sub_len()`, defeating the `saturating_add` guard the *enclosing*
TLV-level `len()` deliberately added. Same raw pattern at:

- `prefix.rs:556` — `IsisTlvExtIpReachEntry::sub_len`
- `prefix.rs:757` — `IsisTlvIpv6ReachEntry::sub_len`
- `prefix.rs:1119` — `Srv6Locator::len`
- `prefix.rs:1191` — `IsisTlvSrv6::len` (`.sum()` then `+ 2`)
- `cap.rs:254` — `IsisTlvRouterCap::sub_len`
- `neigh.rs:792` — `IsisSubAsla::len`

**Failure:** one Extended IS Reachability entry with ~11 `Srv6EndXSid` sub-TLVs
(24 bytes each, ~264 total): `sum::<u8>()` overflows → **debug builds panic**
(`attempt to add with overflow`) while generating an LSP; release builds wrap the
length byte to 8 and emit all 264 bytes, so a receiver parses 8 bytes of subs and
reads the remaining 256 as phantom neighbor entries. A single oversized entry
can't be sharded by the packer (which shards at entry boundaries), so it hits this
per-entry length directly.

**Fixed:** every listed site (plus the same pattern in `IsisSubSrv6EndSid`,
`IsisSubSrv6MirrorSid`, `IsisSubSrv6EndXSid`, `IsisSubSrv6LanEndXSid`) now
computes in `usize` and saturates once at the `u8` boundary with `.min(255)`,
mirroring the pre-existing `IsisSubFlexAlgoDef` idiom, so the packer's
`wire_len()` probe of an over-full entry is debug-safe. The three reach entries
additionally emit their sub-TLV block through `emit_sub_tlvs`, so the sub-length
byte is back-patched from the bytes actually written instead of computed twice.
Unit tests pin a 300-byte sub block saturating to 255 and the back-patch
round-trip.

### 8. 🟠 `emit_sub_tlvs` silently caps the sub-TLV block length at 255 — CONFIRMED — ✅ FIXED
`crates/isis-packet/src/util.rs:13`

`buf[pp - 1] = (buf.len() - pp).min(255) as u8` — a sub-TLV block larger than 255
bytes is labeled 255 while all bytes remain in the stream. Affects
`Srv6Locator::emit` (`prefix.rs:1132`), `IsisSubSrv6EndSid` (`prefix.rs:128`),
`IsisSubSrv6MirrorSid` (`prefix.rs:188`), `IsisSubSrv6EndXSid` (`neigh.rs:978`),
`IsisSubSrv6LanEndXSid` (`neigh.rs:1044`).

**Failure:** an SRv6 Locator whose sub-TLVs serialize to ~276 bytes: the length
byte is clamped to 255 but 276 bytes follow. `Srv6Locator::parse_be` does
`safe_split_at(input, 255)`, slicing mid-sub-TLV; the truncated tail parses as
`Unknown` and the leftover ~21 bytes are consumed as the metric/flags of a
phantom second locator, injecting a bogus SRv6 route at every receiver.

**Fixed:** an over-full block now trips a `debug_assert` at emit time (a
builder bug is caught in dev/test); in release the block is truncated to 255
bytes so the length byte always matches the bytes present — the truncated tail
parses as one malformed sub-TLV instead of desyncing the rest of the PDU into
phantom entries. A `should_panic` unit test pins the assert.

### 9. 🟠 3-octet SID/Label value is never masked to 20 bits — CONFIRMED — ✅ FIXED
`crates/isis-packet/src/parser.rs:1336` (`SidLabelValue::parse_be` / `emit`)

A 3-byte label field is read with `be_u24` into the full 24-bit value. RFC 8667
says only the low 20 bits are the label and the top 4 are reserved. FRR masks this
on unpack (`sid &= MPLS_LABEL_VALUE_MASK`, `../frr/isisd/isis_tlvs.c:1813,1857`);
zebra masks on neither parse nor emit.

**Failure:** a peer that sets any reserved high bit — or an origination path with
a mis-scaled value — yields an illegal MPLS label (≥ 2²⁰) that zebra accepts,
re-advertises verbatim, and can program into the FIB.

**Fixed:** `SidLabelValue::LABEL_MASK` (`0x000F_FFFF`) is applied on both parse
and emit of the 3-octet `Label` form, matching FRR; the 4-octet `Index` form is
untouched. Unit test pins both directions.

### 10. 🟠 One malformed reach entry / sub-TLV silently truncates all that follow — CONFIRMED — ✅ FIXED
`crates/isis-packet/src/sub/prefix.rs:1048` (v4) and `:1072` (v6); sub-TLV `parse_subs` sites

Unlike the top-level TLV loop (which degrades a malformed known TLV to `Unknown`),
a sub-parser error propagates `?` out and the enclosing `many0_complete`
interprets it as end-of-list, silently dropping every following valid
entry/sub-TLV. Reach entries pass a wire prefixlen straight to `ptake`/`ptakev6`
(v4 accepts the 6-bit field 0..63, v6 accepts a u8 0..255).

**Failure:** a TLV 135 whose first entry has control-byte prefixlen 33 (invalid
for v4) followed by a valid /24 entry: `ptake` returns `ErrorKind::Verify`,
`many0_complete` stops, and the second entry is dropped with no error and no
`Unknown` record — silent route loss from a single malformed/malicious peer entry.
Same for TLV 236 (v6 prefixlen > 128) and for a malformed known sub-TLV in any
sub-TLV block.

**Fixed:** two mechanisms. (1) All six sub-TLV registries (`parse_subs` in
`neigh`, `prefix` ×3, `cap` ×2) now degrade a malformed *known* sub-TLV to
`Unknown` with its bytes preserved, mirroring the top-level TLV loop, so
followers still parse. (2) TLV 135/235/236/237 entry lists go through
`parse_reach_entries`, which frames a semantically invalid entry from its
header fields (`ext_ip_reach_entry_span` / `ipv6_reach_entry_span`) and skips
it alone; an unframeable tail errors so the whole TLV degrades to `Unknown`
instead of silently discarding bytes. Unit tests pin the v4 (prefixlen 33) and
v6 (prefixlen 200) skip cases and the sub-TLV degrade.

### 11. 🟡 Reach-entry emit keys the sub-TLV block on `subs.is_empty()` but writes the stored S-flag — PLAUSIBLE — ✅ FIXED
`crates/isis-packet/src/sub/prefix.rs:559` (and `:760` for IPv6)

`emit()` gates the optional sub-TLV-length byte on `self.subs.is_empty()` while
writing the stored `flags` byte verbatim, but the receiver keys the block's
presence on `flags.sub_tlv()`. The codec never reconciles the two sources of
truth.

**Failure:** an entry parsed with `S=1` and `sublen=0` comes back with
`flags.sub_tlv()=true`, `subs=[]`; re-emitting writes `S=1` but omits the sublen
byte, so a receiver reads the next entry's metric MSB as a sub-TLV length and the
TLV desyncs. Symmetrically, a locally-built entry with non-empty `subs` but a
flags value whose `sub_tlv` bit is false emits a block the parser never reads.

**Fixed:** both entry emitters derive the S bit with
`flags.with_sub_tlv(!subs.is_empty())` at emit time, and the TLV 135 emitter
also derives the control byte's 6-bit prefixlen from `prefix.prefix_len()` —
writing the fix surfaced that the prefixlen field had the same two-sources-of-
truth problem (emit counts prefix octets from `prefix` while the receiver
counts from the stored flags). The stored flags are kept verbatim for display
of received packets; the daemon's manual `with_sub_tlv`/`with_prefixlen`
bookkeeping remains valid but is no longer load-bearing. Unit tests pin the
parsed S=1/sublen=0 re-emit and the hand-built subs-without-flag round-trip
for both TLV 135 and TLV 236.

### 12. 🟡 `P2p3Way` / `Restart` parse optionals by remaining length but emit by `Option` — PLAUSIBLE — ✅ FIXED
`crates/isis-packet/src/parser.rs:1168`; `crates/isis-packet/src/sub/restart.rs:83`/`:129`

`IsisTlvP2p3Way::parse_be` assigns optional trailing fields purely by remaining
length in fixed order (circuit_id if ≥4, then neighbor_id if ≥6, then
neighbor_circuit_id if ≥4), while `emit` writes whichever `Option`s are `Some`.
`IsisTlvRestart` has the identical asymmetry.

**Failure:** a `P2p3Way` built with `circuit_id=None, neighbor_id=Some(sysid)`
emits `state + 6 bytes`; the parser takes the first 4 as `circuit_id`, so the
three-way handshake compares the wrong neighbor identity. A `Restart` with
`remaining_time=None` but `restarting_neighbor=Some` emits `flags + 6 bytes`; the
parser reads the first 2 as `remaining_time` and honors a bogus hold-time during
graceful restart. Currently latent because callers set the fields together, but
nothing enforces it.

**Fixed:** both `len()`/`emit()` now enforce prefix-closure — fields are
emitted in wire order and emission stops at the first `None`, so a gapped
struct can never produce a byte layout the length-driven parser would
misassign. All daemon builders were already prefix-closed, so no wire output
changes. Unit tests pin the gapped-struct emit (only the leading fields) and
every prefix-closed `P2p3Way` form round-tripping exactly.

### 13. 🟡 `admin_group()` doc claims sub-TLV 3 but reads sub-TLV 14; sub-TLV 3 undispatched — PLAUSIBLE — ✅ FIXED
`crates/isis-packet/src/sub/neigh.rs:154`

The accessor is documented as returning the sub-TLV 3 Administrative Group but
reads `IsisSubTlv::AdminGrp`, which is the RFC 7308 **Extended** Admin Group
(sub-TLV 14). The classic RFC 5305 Administrative Group (sub-TLV 3) has **no
dispatch arm** in `IsisNeighCode`.

**Failure:** a router advertising link color via the standard sub-TLV 3 lands in
`Unknown`, so the BGP-LS producer calling `admin_group()` gets `None` and the
color is lost. BGP-LS also distinguishes Administrative Group (TLV 1088) from
Extended Administrative Group (TLV 1173), so mapping one to the other is
semantically wrong.

**Fixed:** sub-TLV 3 now has a dedicated `IsisSubAdminGroup` codec (fixed
4-octet mask) and dispatch arm; `admin_group()` reads it (BGP-LS TLV 1088),
and a new `ext_admin_group()` exposes the RFC 7308 sub-TLV 14 list (BGP-LS
TLV 1173 when the producer grows support for it). Display labels the two
flavors distinctly. Unit test pins the dispatch, round-trip, and both
accessors on an entry carrying both flavors.

### 14. 🟡 ASLA parse forces SABM/UDABM to ≥1 byte when L-flag set — PLAUSIBLE — ✅ FIXED
`crates/isis-packet/src/sub/neigh.rs:764`

`parse_be` forces `eff_sabm_len`/`eff_udabm_len` to `max(1)` when the L-flag is
set, while `emit` writes exactly `sabm.len()`/`udabm.len()`. An emitted `L=1`
ASLA with empty masks cannot be read back.

> Note: FRR uses 1-byte app-identifier masks (`ASLA_APP_IDENTIFIER_BIT_LENGTH 1`),
> so the `max(1)` may be defensive rather than clearly wrong. The **asymmetry**,
> not the min itself, is the concern — hence PLAUSIBLE, not CONFIRMED.

**Failure:** a peer (or local build) emits `L=1` with `SABM Length=0,
UDABM Length=0` followed by nested sub-TLVs; the parser applies `max(1)` and
consumes the first two bytes of the first nested sub-TLV (its type and length) as
fabricated masks, then parses the rest at a shifted offset — nested TE attributes
are garbled and re-emission differs from the wire.

**Fixed:** the parser now honors the advertised lengths (the RFC 9479 §4.2
mask lengths are actual octet counts 0–8 with no L⇒1-byte rule — the `max(1)`
comment's claim doesn't match the RFC text, and FRR's 1-byte constant is its
*send*-side choice, not a parse rule), and rejects lengths > 8 so a
non-conformant claim degrades the sub-TLV to `Unknown` (finding #10 machinery)
instead of desyncing. Emit is unchanged; the daemon only builds `l_flag:
false` 1-byte-SABM ASLAs, so no local wire output changes. Unit tests pin the
L=1/empty-mask round-trip (nested sub-TLV intact) and the >8 length degrade.

### 15. 🟡 `IsisPacket::emit` drops Unknown PDU payload; `IsisTlvUnknown` emit doubles the header — CONFIRMED — ✅ FIXED
`crates/isis-packet/src/parser.rs:98` and `:1271`

`IsisPacket::emit` maps `Unknown(_) => {}`, dropping the stored
`IsisUnknown.payload` and emitting an 8-byte header with no body — despite the
payload being preserved on parse. Separately, `IsisTlvUnknown::emit` writes
`typ+len+value` while every other `TlvEmitter::emit` writes value-only, so a
caller using `tlv_emit()` on it (rather than the `emit()` that `IsisTlv::emit`
deliberately calls) produces a doubled `[typ,len,typ,len,...]` header.
`IsisSubTlvUnknown` is modeled correctly, so the two Unknown types disagree on the
contract.

**Failure:** any path that re-emits a parsed packet (padding probe, mirror/replay
tooling, future forwarding of an unrecognized PDU type) silently produces an
empty-bodied PDU instead of the original bytes; and a future generic path using
`tlv_emit()` on `IsisTlvUnknown` emits a malformed doubled header.

**Fixed:** `IsisPacket::emit` re-emits `IsisUnknown.payload` verbatim;
`IsisTlvUnknown::emit` is value-only per the `TlvEmitter` contract (matching
`IsisSubTlvUnknown`), its `len()` derives from `values` instead of the stored
parse-metadata byte, and the `IsisTlv` dispatcher uses `tlv_emit` like every
other variant. Unit tests pin the unknown-PDU byte-exact round-trip and the
single-header TLV emit via both `tlv_emit` and the dispatcher.

---

## Lower-severity SRv6 notes (not ranked)

From the SRv6 deep-dive, worth tracking but below the bar for the ranked list:

- **SID width from byte-count, not flags** (`parser.rs:1338`) — ✅ FIXED:
  `SidLabelValue::parse_be_flags` makes the RFC 8667 V/L flags authoritative at
  the Prefix-/Adj-/LAN-Adj-SID sites (V=L=1 label, V=L=0 index; any other
  combination or a flag/width mismatch degrades the sub-TLV to `Unknown`), and
  the three emitters derive V/L from the SID variant (the finding-#11 policy).
  The width-by-length `parse_be` remains only for Binding TLV 149's SID/Label
  sub-TLV, where RFC 8667 §2.3 keys the form on the length.
- **SRGB/SRLB `range` truncation** (`cap.rs:116`, `:182`) — ✅ FIXED: emit
  saturates the range at `0x00FF_FFFF` instead of letting `u32_u8_3` wrap it.
- **SID Structure bounds** (`prefix.rs:274`) — ✅ FIXED: `IsisSub2SidStructure`
  rejects LB+LN+Fun+Arg sums over 128 bits; the registry degrades the claim to
  `Unknown`.
- **`End.M = 74`** (`srv6.rs:334`) — ✅ VERIFIED (2026-07-18): the IANA "SRv6
  Endpoint Behaviors" registry assigns value 74 (0x004A) to "End.M (Mirror
  SID)" with reference `draft-ietf-rtgwg-srv6-egress-protection-02`; the
  crate's codepoint is correct.

---

## Verified clean (so they are not re-flagged)

- **All type-code tables** — TLV codes, cap/neigh/prefix sub-TLV codes, FAD
  sub-codes, and the SRv6 endpoint-behavior codepoints (End/End.X/End.T/DT*/B6/
  USD/NEXT-CSID/REPLACE-CSID) — match IANA/RFC and FRR; the `Behavior` table is
  pinned by a bidirectional test.
- **Flag bit positions that are correct** (checked vs FRR): `AdjSidFlags`
  (F/B/V/L/S/P), `PrefixSidFlags` (R/N/P/E/V/L), `BindingFlags` (F/M/S/D/A),
  `SegmentRoutingCapFlags` (I=0x80/V=0x40), the SRv6-Capabilities `Srv6Flags`
  O-flag (`0x4000`), the `MultiTopologyId` LSB-first fix, and `Restart` RR/RA/SA.
- **All `From<u8>`/`From<u16>` conversions** fall through to `Unknown`/`Resv` — no
  panics on unknown values.
- **Endianness** is uniformly big-endian (`be_*`, `to_be_bytes`,
  `BigEndian::write_u16`).
- **Bounds safety**: `ptake`/`ptakev6` validate prefix length and buffer length
  before slicing; `safe_split_at` guards every length-driven split on the parse
  path; `many0_complete` sub-parsers all consume ≥1 byte (no infinite loops).
- The SRLG, Auth (cleartext/HMAC-MD5/generic), Restart, FAD, and RFC 8570
  delay/bandwidth codecs round-trip correctly and are well-tested.
- No CLAUDE.md rule is violated by the crate source (the only governing file
  holds git/test/BDD-workflow rules that don't constrain static codec source).

---

## Non-blocking cleanups (quality, not correctness)

Correctness outranks these for the ranked list, but they're worth scheduling:

- **Sub-TLV dispatch boilerplate** is copy-pasted verbatim across 6 registries
  (`neigh.rs:251`, `prefix.rs:242`/`:310`/`:343`, `cap.rs:37`/`:543`) — read
  code+len → `safe_split_at` → dispatch → hand-patch the `Unknown` code/len. The
  length-prefixed sub-block parse (`read u8 len → safe_split_at →
  many0_complete`) is re-implemented at 7 more sites. Both have precedent helpers
  in the crate (`util::emit_sub_tlvs`, `safe_split_at`, `many0_complete`); a
  single generic helper per shape would remove ~250 lines and the risk of a
  seventh copy dropping the `Unknown` patch.
- **`IsisTlv::wire_len()`** (`parser.rs:585`) measures a TLV by allocating a fresh
  `BytesMut` and fully serializing it; the LSP packer (`lsp.rs:203`) calls it on a
  clone of the growing TLV after every entry pushed → O(n²) alloc+serialize per
  LSP regeneration. A `usize`-returning value-length (summing the existing
  per-entry math) makes it `2 + value_wire_len()` with zero allocation.
- **`padding.rs`** duplicates a ~55-line function verbatim for `IsisHello` and
  `IsisP2pHello` (including a nested `fn padding_tlv` defined twice).
- The three RFC 8570 bandwidth sub-TLVs (`IsisSubResidualBw`/`AvailableBw`/
  `UtilizedBw`, `neigh.rs:651`/`:683`/`:715`) are identical one-field wrappers
  differing only by code point.
- Seven `is_empty()` methods (`SidLabelValue` and the sub-TLV enums) can never
  return `true` and have no callers.

---

## Suggested priority

**All 15 ranked findings are fixed** — PRs #1952 (#1), #1957 (#2), #1961
(#3/#5), #1964 (#4/#7/#8), #1967 (#6/#9/#10), #1969 (#11), #1971 (#12),
#1975 (#13), #1977 (#14), #1978 (#15). The original triage order is kept
below for the record:

1. ~~Fix #1 (LspEntries wrap) first~~ — **done** (PR #1952): builders capped at
   15 entries per TLV; unit + BDD regression coverage in place.
2. ~~Fix #2 (RouterCap S/D) and #5 (Srv6TlvFlags MTID)~~ — **done**: both
   bitfields declared LSB-first with the bit positions pinned by unit tests.
3. ~~Fix #3 (nsap panic)~~ — **done**: system-id groups are length-checked
   before indexing; malformed `net` config now returns `NsapParseError`.
4. ~~Work through the emit-side length cluster (#4, #7, #8)~~ — **done**:
   TLV 6 capped + sharded, all per-entry length sums are `usize`-with-`min(255)`,
   and `emit_sub_tlvs` asserts/truncates instead of mislabeling an over-full
   block.

---

## Follow-up work (priority order)

What remains after the ranked findings: the SRv6-note tail and the cleanup
backlog, ordered by risk and value.

1. ~~**`SidLabelValue` width from the V/L flags, not byte count**~~ — **done**:
   `parse_be_flags` (flags-authoritative, mismatch → `Unknown`) wired into the
   Prefix-/Adj-/LAN-Adj-SID parsers; emit derives V/L from the variant. The
   byte-count parse remains only for Binding TLV 149 per RFC 8667 §2.3.
2. ~~**Verify `End.M = 74` against IANA**~~ — **done**: IANA assigns 74 to
   "End.M (Mirror SID)" (`draft-ietf-rtgwg-srv6-egress-protection-02`); the
   crate is correct, no code change.
3. ~~**Parse-hardening pair**~~ — **done**: `IsisSub2SidStructure` rejects
   >128-bit sums (degrades to `Unknown`); SRGB/SRLB emit saturates the 24-bit
   range instead of wrapping.
4. ~~**O(n²) `wire_len()` packer probe**~~ — **done**: the entry-bearing TLVs
   (and RouterCap) expose an unsaturated `value_wire_len()`, `IsisTlv::wire_len`
   is `2 + value` computed arithmetically, and the splitter probes the growing
   TLV via the `SplittableTlv` trait with no clone and no serialization. A
   unit test pins `wire_len == emitted bytes` across variants including an
   over-full TLV 135.
5. **Dedup the six sub-TLV dispatch registries** — the #10 fix made each copy
   bigger (the degrade-to-Unknown match is pasted six times); one generic
   helper removes ~250 lines and the risk that a seventh registry forgets the
   Unknown patch or the degrade.
6. **BGP-LS Extended Admin Group (TLV 1173) producer** — enabled by #13:
   `ext_admin_group()` exists, but there is no `BGPLS_ATTR_EXT_ADMIN_GROUP`
   constant, so links advertising only the RFC 7308 group export no color at
   all (the old, wrong 1088 mapping was removed deliberately).
7. **Small-cleanup sweep (one PR)** — the duplicated ~55-line padding function
   (`IsisHello`/`IsisP2pHello`), the three identical RFC 8570 bandwidth
   wrappers, and the seven dead `is_empty()` methods.
8. **Optional: live interop validation** — the flag/bit fixes (#2, #5, #13,
   #14) are unit-tested against FRR's *source*; a BDD or lab run against a
   real FRR/IOS neighbor exercising RouterCap S-flag, multi-area TLV 1, and
   MT SRv6 would close the loop the way the Cisco interop work did for TLV
   parsing.
