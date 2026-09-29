# OSPFv3 Segment Routing on the standard encodings — design

> **Status:** reviewed (2026-09-29); all five §8 decisions settled, each taking the
> recommendation: phased over two releases, the legacy carrier dual-originated for one release
> with no knob, PR 1 first, the interop peer chosen later, OSPFv2's capability bits.
> **Parent docs:** [ospf-sr-mpls-status.md](./ospf-sr-mpls-status.md) (records the current carrier
> as "placement by convention, not by RFC fiat"), [ospfv3-srv6-plan.md](./ospfv3-srv6-plan.md),
> [flex-algo-link-loss.md](./flex-algo-link-loss.md) (PR 3b chose to stay on the current carrier
> and defer this move)
> **Branch:** `ospfv3-ri-lsa-design`

---

## 1. Why / scope

zebra-rs's OSPFv3 Segment Routing works between zebra-rs routers and with no one else. Its SR
capabilities — SR-Algorithm, SRGB, SRLB, Flexible Algorithm Definitions, SRv6 Capabilities —
ride a zebra-rs-only E-Router-LSA instance, where RFC 8666 and RFC 9350 put them in the OSPFv3
Router Information LSA (RFC 7770). The research for this document found that the carrier is not
the only problem:

- **Two sub-TLV code points are wrong.** zebra-rs sends the Adj-SID as sub-TLV 6 and the LAN
  Adj-SID as 7; RFC 8666 assigns 5 and 6. The SID/Label sub-TLV nested in the SRGB and SRLB TLVs
  is sent as 5; RFC 8665 assigns 1.
- **A standard router's LAN Adj-SID makes zebra-rs drop its whole LS Update.** Sub-TLV 6 from a
  standard router is a LAN Adj-SID (11 or 12 octets); zebra-rs parses it as its P2P Adj-SID,
  rejects the SID length, and the error propagates out of the Router-Link TLV, the LSA and the LS
  Update (verified: `Ospfv3Lsa::parse_be` returns `Incomplete(Size(7))`). The sender retransmits
  forever; every LSA in that update is lost, not just the SR one. This is an interop failure today,
  independent of the rest of this design.

This design moves OSPFv3 SR onto the standard encodings in both directions, and makes the move
safe for a network upgraded router by router.

In scope: the OSPFv3 RI LSA (receive and originate), the Adj-SID / LAN Adj-SID / SID/Label
sub-TLV code points, decode robustness for Extended-LSAs, and the transition. Out of scope, with
reasons, in §7.

## 2. What the specifications require

**RFC 7770** (OSPF Router Information):
- §2.2: the OSPFv3 RI LSA has function code 12; "The U bit will be set indicating that the
  OSPFv3 RI LSA should be flooded even if it is not understood"; S1/S2 give the scope. Area scope
  is LS type **0xA00C**. "The Link State ID (LSID) value for this LSA is the Instance ID."
- §2.3: TLVs are Type(2) / Length(2) / Value, padded to 4 octets, padding not in the length.
- §2.4: the Router Informational Capabilities TLV (type 1), "If included, it MUST be the first TLV
  in the first instance, i.e., Instance 0".
- §3: a TLV in several instances, where its own RFC says nothing else: "the ... TLV in the Router
  Information LSA with the numerically smallest Instance ID will be used and subsequent instances
  will be ignored."

**RFC 8666** §4 (OSPFv3 SR): "These SR capabilities are advertised in the OSPFv3 Router
Information Opaque LSA (defined in [RFC7770]) and specified in [RFC8665]." §7.1/§7.2 and IANA
§9.2 ("OSPFv3 Extended-LSA Sub-TLVs"): Prefix-SID **4**, Adj-SID **5**, LAN Adj-SID **6**,
SID/Label **7**. §9.1 ("OSPFv3 Extended-LSA TLVs"): **9** = OSPFv3 Extended Prefix Range TLV.

**RFC 8665** §3 (the RI TLVs, shared by OSPFv2 and OSPFv3): SR-Algorithm **8** ("the receiver MUST
use the first occurrence"); SID/Label Range **9** (MAY repeat; the receiver MUST keep the
advertised order; its SID/Label sub-TLV is type **1**, and only one is allowed); SRLB **14**;
SRMS Preference 15. Area scope is REQUIRED for SR-Algorithm, SRGB and SRLB.

**RFC 9350** §5.2: the FAD TLV (**16**) is "a top-level TLV of the Router Information (RI) LSA";
area scope REQUIRED; for one algorithm the receiver uses the first occurrence, the area-scoped RI
LSA over an AS-scoped one, and the smallest Instance ID. Its sub-TLV registry (1–5) is shared by
OSPFv2 and OSPFv3. §11.1: participation is the SR-Algorithm TLV.

**RFC 9513** §2: the SRv6 Capabilities TLV (**20**) is "an optional top-level TLV of the OSPFv3
Router Information LSA", area scope REQUIRED; SRv6 algorithm support uses the RFC 8665
SR-Algorithm TLV in the same LSA. §7: the SRv6 Locator LSA is function code 42 (zebra-rs already
originates it correctly, 0xA02A).

## 3. Where zebra-rs stands

### Wire encodings

| What | Standard | zebra-rs today |
|---|---|---|
| SR capabilities carrier | RI LSA 0xA00C, instance 0 | E-Router-LSA 0xA021, LS-ID 0 |
| SR-Algorithm TLV | RI TLV 8 | Extended-LSA TLV 9 (= Extended Prefix Range TLV in IANA) |
| SID/Label Range TLV | RI TLV 9 | Extended-LSA TLV 10 (unassigned) |
| SR Local Block TLV | RI TLV 14 | Extended-LSA TLV 11 (unassigned) |
| FAD TLV | RI TLV 16 | Extended-LSA TLV 16 (unassigned) |
| SRv6 Capabilities TLV | RI TLV 20 | Extended-LSA TLV 20 (unassigned) |
| SID/Label sub-TLV in SRGB/SRLB | 1 | 5 |
| Adj-SID sub-TLV | 5 | 6 |
| LAN Adj-SID sub-TLV | 6 | 7 |
| Prefix-SID sub-TLV | 4 | 4 (correct) |
| ASLA, SRv6 End.X / LAN End.X / SID Structure | 11, 31, 32, 30 | same (correct) |

The carrier was a local convention (ospf-sr-mpls-status.md: "placement by convention, not by
RFC fiat"), and the SID/Label type 5 was flagged there as "a best-effort reading ... Verify
against a real peer".

### What each side makes of the other today

- **A standard router receiving zebra-rs:** it finds no RI LSA from zebra-rs, so it has no SRGB
  and installs none of zebra-rs's Prefix-SIDs. It reads zebra-rs's P2P Adj-SID (6) as a malformed
  LAN Adj-SID, and its LAN Adj-SID (7) as a SID/Label sub-TLV. The LS-ID 0 E-Router-LSA carries a
  TLV 9 that the registry says is an Extended Prefix Range TLV. It most likely ignores that, but
  the lab has to confirm.
- **zebra-rs receiving a standard router:** it stores and floods the RI LSA (it floods by the scope
  bits, so the unknown type passes), but reads nothing from it, so it has no SRGB, algorithms or
  definitions for that router. A P2P Adj-SID (5) is ignored as unknown. A LAN Adj-SID kills the
  whole LS Update (§1).
- **Decode robustness:** an unparseable TLV or sub-TLV in any Extended-LSA fails the LSA, and the
  LS Update parser propagates that (`Ospfv3Lsa::parse_be(start)?`), so one bad element costs the
  whole packet. PR 3a/3b made FAD sub-TLVs tolerant; nothing else in the Extended-LSAs is.

### Code that reads or writes the carrier

All of it lives in `zebra-rs/src/ospf/`:

| Role | Where |
|---|---|
| Builder | `srmpls.rs` `e_router_v3_sr_info_lsa_build` |
| Originator | `inst.rs` `e_router_v3_sr_info_lsa_originate` |
| Originator callers | SR mode, flex-algo readvertise, SRv6 locator, Enable, Router-ID, self-originated echo |
| SRGB/SRLB cache | `lsdb.rs` `update_lsa_v3`, `label_map_resync_v3`, `e_router_label_blocks` |
| Flex-Algo readers | `inst.rs` `flex_algo_peer_fads_v3`, `flex_algo_participants_v3` |
| Display | `show_v3.rs` database detail; `show ospfv3 segment-routing` reads the SRGB/SRLB cache |

The OSPFv2 codec already implements the RI LSA body (`parser.rs` `RouterInfoLsa` / `RouterInfoTlv`:
types 1, 8, 9, 14, 16, with the SID/Label sub-TLV as type 1), and its capability bits match
RFC 7770 §2.4. The RI TLV registry is shared between OSPFv2 and OSPFv3, so the OSPFv3 RI LSA can
reuse that codec; it only lacks SRv6 Capabilities (20), which today falls to `Unknown`.

## 4. Design

### D1 — Decode robustness and both Adj-SID encodings (PR 1)

- **Contain errors.** A known Extended-LSA TLV or sub-TLV whose value does not parse is kept as
  unknown, bytes and all, as PR 3a/3b did for FAD sub-TLVs. It re-floods as received and nothing
  computes with it. One that overruns its container is kept as trailing bytes. An LSA whose body
  still fails is installed with an opaque body — flooded, never used — instead of failing the LS
  Update. One malformed element must never cost the packet.
- **Read both Adj-SID encodings.** The two layouts differ in length, so the decoder can tell them
  apart. This lets PR 1 read standard routers and older zebra-rs alike:

  | Sub-TLV | Length 7/8 (SID 3/4) | Length 11/12 (neighbour ID + SID) | Length 3/4 |
  |---|---|---|---|
  | 5 | Adj-SID (standard) | — | — |
  | 6 | Adj-SID (zebra-rs today) | LAN Adj-SID (standard) | — |
  | 7 | — | LAN Adj-SID (zebra-rs today) | SID/Label (standard; not valid here → unknown) |

- **Decode the RI LSA.** Add `Ospfv3LsBody::RouterInfo(RouterInfoLsa)` for 0xA00C — and the link-
  and AS-scoped 0x800C / 0xC00C, so they display — reusing the shared codec, and add RI TLV 20
  (SRv6 Capabilities) to `RouterInfoTlv`. Its body reuses today's `Ospfv3Srv6CapabilitiesTlv`.
  `show ospfv3 database` names it `Router-Info-LSA`; `detail` renders its TLVs with the lines the
  SR-info rendering prints today (`Algorithm 128: …`, `SRv6 Capabilities TLV`), so the existing
  features' assertions hold.

Sending is unchanged, so PR 1 is safe in any mix. It fixes the LS Update drop on its own.

### D2 — Read SR capabilities from the RI LSA (PR 2)

Per area, per advertising router, from its area-scoped RI LSAs (0xA00C) in ascending Instance ID,
MaxAge ones excluded:

- **SR-Algorithm:** the first occurrence (RFC 8665 §3.1). This covers participation, and SRv6
  algorithm support.
- **SRGB and SRLB:** the first SID/Label Range TLV and the first SRLB TLV, in that order. zebra-rs
  models one range of each (as OSPFv2 does today), so a second range is ignored (§7).
- **FAD:** per algorithm, the first occurrence and the smallest Instance ID (RFC 9350 §5.2), into
  the protocol-neutral selection as today (`fad_view` over the shared RI FAD type).
- **SRv6 Capabilities:** the first occurrence.

**Source precedence.** A router that advertises any of these in an RI LSA is read from its RI LSAs
alone. A router that does not — an older zebra-rs — is read from the legacy E-Router carrier,
exactly as today. So no router is ever read from a mixture, and a network mid-upgrade computes
consistently.

**Derived state.** The SRGB/SRLB cache (`label_map`) is fed and resynced from the RI LSA on
arrival, flush and expiry, with the same rules #2427/#2428 gave the legacy carrier. Flex-Algo
participation and definitions read through the same precedence. Receipt already schedules SPF for
every area-scoped LSA, and expiry does too.

### D3 — Originate the RI LSA (PR 3)

- **Which LSA:** one per area where SR-MPLS or SRv6 is on (today's SR-info gating), LS type 0xA00C,
  Instance 0.
- **Triggers:** the same as today's SR-info LSA, including #2430's Enable / first-interface-in-area
  and Router-ID change, the flex-algo commit readvertise, refresh, and the self-originated echo.
- **Content, in order:**
  1. Router Informational Capabilities (type 1) first, as RFC 7770 §2.4 requires of instance 0, with
     the OSPFv2 builder's bits: GR helper, GR capable while restarting, TE.
  2. SR-Algorithm (8), announcing SPF and the Flex-Algorithms this router participates in, in that
     area.
  3. SID/Label Range (9), whose SID/Label sub-TLV is type 1.
  4. SRLB (14).
  5. FAD (16), for each advertised definition.
  6. SRv6 Capabilities (20), when SRv6 is active.
- **The legacy carrier during transition:** it is originated alongside, unchanged, so older
  zebra-rs routers keep reading this router (D5).

After PR 3, standard routers learn zebra-rs's SRGB, algorithms and definitions, and zebra-rs learns
theirs.

### D4 — Send the standard Adj-SID code points (PR 4)

Send Adj-SID as 5 and LAN Adj-SID as 6. Every zebra-rs router in the area must already run PR 1.
A router without PR 1 ignores type 5, losing this router's P2P Adj-SIDs, and drops the whole LS
Update on a standard LAN Adj-SID (§1).

### D5 — Transition

The ordering makes every step compatible with the one before:

| Pair | After PR 1–3 (release N) | After PR 4–5 (release N+1) |
|---|---|---|
| new ↔ old zebra-rs (before N) | Compatible. Old reads the legacy carrier; new reads both. Adj-SIDs are still sent the old way. | Not compatible: an old router drops LS Updates carrying a standard LAN Adj-SID, and loses the SR capabilities once the legacy carrier is flushed. |
| new ↔ zebra-rs N | Compatible | Compatible |
| new ↔ standard router | SR capabilities both ways from PR 3. Adj-SIDs are read from them from PR 1; ours are wrong to them until PR 4. | Fully standard |

So the upgrade rule is: every OSPFv3 SR router runs release N before any runs N+1. PR 5 stops
originating the legacy carrier (flushing it once) and keeps reading it for one more release, so a
router upgraded straight from before N to N+1 still reads peers that were on N.

### D6 — Show and BDD

- **Show:** `show ospfv3 segment-routing` is unchanged (derived state). The database views gain the
  RI LSA (D1).
- **BDD:** every step keeps the existing OSPFv3 SR, SRv6, TI-LFA and Flex-Algo features green. The
  features that read the SR-info rendering (`ospfv3_flexalgo`: `Algorithm 128:`; `ospfv3_srv6`:
  `SRv6 Capabilities TLV`) keep passing because the RI rendering prints the same lines. After
  PR 5 they exercise the RI path alone.

## 5. Testing

- **Codec (PR 1):**
  - byte layouts transcribed from the RFCs: RI LSA TLVs, SID/Label sub-TLV type 1, Adj-SID 5,
    LAN Adj-SID 6;
  - both encodings of each Adj-SID decoded to the same value;
  - an LS Update holding one malformed sub-TLV still yields every LSA — the regression for §1.
- **Receive (PR 2):**
  - vendor-shaped RI LSAs: TLVs split across instances 0 and 1, FAD in both, SRGB in instance 0 only;
  - a router with both carriers is read from the RI LSA;
  - a router with only the legacy carrier is still read;
  - SRGB cache resync on RI expiry.
- **Originate (PR 3):** RI LSA content and TLV order, dual carrier, and the #2430 triggers,
  reusing the `sr_origination_tests` harness.
- **Mutation-test** each rule, as in the Flex-Algo work.
- **Interop lab:** FRR's ospf6d has no OSPFv3 Segment Routing, so FRR cannot be the peer. It needs a
  commercial NOS; §8 decision 3.

## 6. Delivery — smallest PR first

1. **Decode robustness and both Adj-SID encodings, and decode/show the RI LSA** (D1). No send-side
   change. It fixes today's LS Update drop. This is the most urgent, and it could land before the
   rest is decided.
2. **Read SR capabilities from RI LSAs, with legacy fallback** (D2).
3. **Originate the RI LSA alongside the legacy carrier** (D3).

   — Release N: PRs 1–3. —

4. **Send the standard Adj-SID code points** (D4).
5. **Stop originating the legacy carrier; book and doc updates** (D5). This drops ch-15-10's
   "interoperate between zebra-rs routers only" and retires the SR-info notes in
   ospf-sr-mpls-status.md and ospfv3-srv6-plan.md.

   — Release N+1: PRs 4–5, with the upgrade rule in the release notes. —

## 7. Out of scope, and why

- **Multiple SRGB/SRLB ranges.** zebra-rs models one of each in OSPFv2 and OSPFv3 alike; a second
  range is ignored, as today. That is separate work touching label allocation.
- **SRMS Preference, and the SR Mapping Server.** zebra-rs has no mapping server.
- **AS- and link-scoped RI LSAs for SR.** RFC 9350 prefers area scope, and SR-Algorithm, SRGB and
  SRLB are area-scoped by requirement. They are decoded and shown (D1), not used.
- **The OSPFv3 Extended Prefix Range TLV (9) and RFC 8362 full extended-LSA mode.** zebra-rs runs
  legacy LSAs plus the E-LSAs it needs.

## 8. Decisions for the reviewer

*All five settled on 2026-09-29, each as recommended.*

1. **Phased or flag day.** Phased (release N: PRs 1–3; N+1: PRs 4–5) keeps a rolling upgrade
   working. A flag day is one release, but mixed old/new routers break mid-upgrade (D5).
   *Recommend phased.*
2. **Dual-originate the legacy carrier in release N.** Without it, older zebra-rs routers lose
   every new router's SRGB the moment it upgrades. The cost is one release of an E-Router-LSA whose
   TLV 9 a standard router may parse as an Extended Prefix Range TLV. It is likely ignored; the
   lab checks it. *Recommend dual for one release, no knob.* A knob to turn it off, only if the lab
   shows a vendor rejecting it.
3. **Interop peer.** FRR is out (§5). Candidates: Juniper (vJunos / cRPD), Nokia SR OS or SR Linux,
   Cisco XRd, Arista cEOS — which of them implement OSPFv3 SR (and Flex-Algo) is not surveyed
   here. *Recommend picking the one you can run, and treating the lab as validation after merge,
   not as a gate on PRs 1–3.*
4. **RI capability bits.** *Recommend mirroring OSPFv2's builder:* GR helper, GR capable while
   restarting, TE.
5. **PR 1 ahead of the rest.** It fixes a live interop failure and changes nothing sent.
   *Recommend landing it first, before decisions 1–4 are settled.*

## Sources

- [RFC 7770](https://www.rfc-editor.org/rfc/rfc7770.html) §2.2–§2.4, §3;
  [RFC 8665](https://www.rfc-editor.org/rfc/rfc8665.html) §3.1–§3.4;
  [RFC 8666](https://www.rfc-editor.org/rfc/rfc8666.html) §4, §6, §7.1, §7.2, §9;
  [RFC 9350](https://www.rfc-editor.org/rfc/rfc9350.html) §5.2, §11.1;
  [RFC 9513](https://www.rfc-editor.org/rfc/rfc9513.html) §2, §7;
  [RFC 8362](https://www.rfc-editor.org/rfc/rfc8362.html)
- IANA: [OSPFv3 parameters](https://www.iana.org/assignments/ospfv3-parameters/) (LSA function
  codes, Extended-LSA TLVs, Extended-LSA sub-TLVs);
  [OSPF parameters](https://www.iana.org/assignments/ospf-parameters/) (RI TLVs, FAD sub-TLVs)
- [FRR ospf6d documentation](https://docs.frrouting.org/en/latest/ospf6d.html) (no Segment Routing)
- In tree: `crates/ospf-packet/src/v3.rs` (code points at the `OSPFV3_EXT_TLV_*` /
  `OSPFV3_SUB_TLV_*` constants), `crates/ospf-packet/src/parser.rs` (`RouterInfoLsa`),
  `docs/design/ospf-sr-mpls-status.md`
