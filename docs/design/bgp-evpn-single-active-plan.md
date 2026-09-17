# EVPN Single-Active — Design & Phasing Plan (RFC 9785 · rfc7432bis L2-Attr · RFC 9722)

Making `redundancy-mode single-active` behave the way an operator expects:
**one PE forwards everything on a segment, the others stand by, and the
switch-over is a signalled role change rather than a re-convergence.**

The multihoming *forwarding* behaviours are already built and merged (non-DF
BUM filter, split horizon, ES nexthop group, single-active bidirectional
block, pre-installed backup path). What is missing is the three control-plane
pieces a reviewer on the ZebOS side named after building the same thing
there — election granularity, ingress→DF steering, and synchronized carving.
This plan turns those three into zebra-rs work.

Read together with:
- [`bgp-evpn-ethernet-segment.md`](bgp-evpn-ethernet-segment.md) — the ES/DF
  foundation (Phases 1–5, merged). Its "Status (2026-07-01)" table predates
  HRW, preference, AC-DF and the whole dataplane arc; treat the source as
  the baseline, not that table.
- [`bgp-evpn-multihoming-dataplane.md`](bgp-evpn-multihoming-dataplane.md) —
  why multihoming is cradle-only and what the tee already programs.
- [`bgp-evpn-mh-frr-interop-lab.md`](bgp-evpn-mh-frr-interop-lab.md) — the
  (not yet executed) wire-agreement lab; phases P1/P4 are where the
  preference and DP tie-break questions in §3 get settled against FRR.

Branch: `evpn-single-active`.

> This plan **absorbs** `bgp-evpn-single-active.md`, the design write-up
> produced concurrently by another session in this worktree. The two agreed on
> every protocol choice; what that document added — the acceptance scope
> (§1.1), the AC-DF caveat on per-PE determinism (§3.5), the role-update and
> forwarding-safety invariants (§4.5), the richer remote-state provenance
> (§4.3/§4.4), concurrent-recovery handling (§5.3), and the acceptance
> topology and measurements (§8.1) — is folded into the sections below and
> itemized in Appendix C. That file is left on disk untracked; delete it once
> you are satisfied nothing was lost.

## 1. What "single-active" means, and where RFC 7432 stops

RFC 7432 §14.1.1 defines single-active as *per-service*: the DF for
`<ES, Ethernet Tag>` forwards, everyone else blocks. The DF is elected by
service carving — `tag mod N` over the address-ordered PEs (§8.5) — so on a
segment with two PEs, the odd VLANs land on one PE and the even ones on the
other. That is a load-balancing answer to a redundancy question. The operator
who asked for single-active almost always meant *this PE is active, that PE
is standby*, for every service on the segment.

Three gaps follow, and they are exactly the reviewer's three points:

| # | Gap | Today in zebra-rs | This plan |
| - | --- | ----------------- | --------- |
| 1 | Election granularity — DF must be choosable per **PE**, not per `<ES, tag>` | Alg 0 carving (default), Alg 1 HRW, Alg 2 preference all implemented; preference already gives a per-segment winner | Finish RFC 9785: DP bit, correct default preference, `0` as a legal value, optional Alg 3; document the "same preference on every ES of a PE" recipe. Reject RFC 9786 port-active as the primary answer (§3.2) |
| 2 | Nothing in RFC 7432 tells an **ingress** PE which PE is the DF for known unicast | `es_sa_primary` *infers* it from how many Type-2s each PE advertises with that ESI | Signal it: L2-Attr EC P/B on the E-LAN per-EVI A-D (rfc7432bis §7.11.1), both paths kept installed, activate/deactivate on the bit change; keep inference as the compatibility fallback |
| 3 | Link-up hold (3 s) vs. peers re-electing the instant they see the route ⇒ a window with **no DF or two DFs** | `startup-delay` withholds our ES routes entirely; peers re-elect immediately when they arrive | RFC 9722: SCT extended community on the Type-4, T capability bit, everyone carves at the same announced instant, incumbent DF steps down `skew` earlier |

Gap 2 and gap 3 matter far more under single-active than under all-active: a
non-DF that forwards for a moment is a *loop* on a bridged segment, and a
moment with no DF is a black hole for the whole VLAN, not one flow.

### 1.1 Scope and acceptance

**In scope for the first release:** E-LAN over **VXLAN** with the cradle
datapath, on a fabric that includes **two route reflectors**, with all-active
and RFC 8214 VPWS behaviour unchanged throughout. The control-plane state and
the tee messages are encapsulation-neutral, so MPLS and SRv6 inherit them —
but neither is *claimed* until a packet test proves it, the way every other
EVPN row in `bgp-evpn-support-status.md` is claimed.

**Explicitly not claimed:**

- **Whole-PE fate sharing.** Election stays per `(ES, service)`; identical
  preference ordering on every segment makes one PE win everywhere *while all
  members are equally eligible*, but a single access-circuit failure changes
  eligibility on one segment alone (§3.5). Failing over every segment of a PE
  together needs a health policy above the ES, which this plan does not build.
- **Zero loss.** Failover removes route/FIB preparation delay, not detection
  or election delay, and the ingress role update travels on its own BGP
  schedule (§5.4). Report measured loss; do not promise a number that has not
  been measured on the bench in §8.1.

## 2. What is already on main (do not re-derive)

| Building block | Where |
| -------------- | ----- |
| DF Election EC codec, Alg 0/1/2 constants, AC-DF bit, 2-octet preference field | `crates/bgp-packet/src/attrs/ext_com.rs:388,527` |
| ESI Label EC with the Single-Active flag, on the per-ES A-D | `ext_com.rs:397`; `bgp/route.rs:18395` |
| L2-Attr EC (P/B/C + MTU) codec — used by VPWS only so far | `ext_com.rs:406,412`; `bgp/route.rs` VPWS origination |
| Election: carving, HRW (CRC-32 digest + weight), preference ranking, backup = runner-up | `bgp/ethernet_segment.rs:230,292,265,346` |
| Algorithm negotiation (unanimity, else fall back to Alg 0) | `ethernet_segment.rs:217` |
| AC-DF (RFC 8584 §4): unanimity gate + per-(EVI,tag) candidate narrowing | `ethernet_segment.rs:502`; `route.rs:19562,19604` |
| E-LAN DF verdict per `(ESI, VNI)`, teed to cradle as `EsRole{df, single_active}` | `ethernet_segment.rs:453`; `route.rs:19216`; `rib/inst.rs:514` |
| Startup hold (`df-election startup-delay`): withholds Type-4 + per-ES A-D, re-originates on expiry | `ethernet_segment.rs:169`; `route.rs:19432,19683` |
| ES nexthop group per `(ESI, bd)`, single-active ⇒ ordered DF-first, rest = pre-installed backup path | `route.rs:19061`; `ethernet_segment.rs:472`; `rib/inst.rs:535` |
| Single-active primary **inferred** from selected Type-2 counts | `route.rs:19170` |
| Split horizon (local bias / ESI label), LAG-as-port, MPLS ESI labels | merged; see the dataplane doc |
| cradle: `ES_DF_F_BLOCK` bidirectional standby block, `ES_NHG` slot-0-only under single-active | cradle-rs #188, #189 |

So the *enforcement* side of single-active is done. Everything below is about
**who is elected, who is told, and when**.

## 3. Gap 1 — electing per PE, not per VLAN

### 3.1 Why carving and HRW cannot express it

`elan_df()` elects with the VNI as the Ethernet Tag, so a PE pair carving two
VNIs splits them one each. HRW spreads the same way (that is its purpose —
minimal disruption, not determinism). Neither has a knob that says "this PE".

### 3.2 RFC 9786 Port-Active is not the answer here

RFC 9786 (Port-Active Redundancy Mode) does move the granularity: DF Election
capability **bit 5** ("Port Mode DF Election", bitmap value `0x0400`) tells
the segment to elect at `<ES>` scope only, ignoring Ethernet Tags, with the
modulus taken over *bytes 3–6 of the ESI* (HRW and preference variants are
also allowed, and AC-DF must be 0 in port mode). The standby port is blocked
for all VLANs, like single-active but interface-wide.

That gives *one DF per ES* — which is a real improvement, and is what most
vendors' "port-active" means — but it does **not** give one DF per PE: a PE
holding ES-1 and ES-2 can be DF for one and non-DF for the other, because
each ES runs its own modulus. The reviewer's conclusion is correct.

Port-active remains worth implementing later for the LAG/standby-port
semantics (port down / LACP out-of-sync on the standby), tracked as a
follow-up, not part of this plan.

### 3.3 RFC 9785 preference-based election — the mechanism we adopt

Wire format (RFC 9785 §3), on the Type-4 DF Election EC we already emit:

```
 0                   1                   2                   3
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Type=0x06     | Sub-Type(0x06)| RSV |  DF Alg |    Bitmap     ~
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
~     Bitmap    |   Reserved    |   DF Preference (2 octets)    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

Bitmap (MSB-0):  bit 0 = D (Don't Preempt)   -> 0x8000
                 bit 1 = A (AC-DF, RFC 8584) -> 0x4000   [have]
                 bit 3 = T (RFC 9722)        -> 0x1000   [§5]
                 bit 5 = Port Mode (RFC 9786)-> 0x0400   [not planned]

DF Alg:  0 Default carving · 1 HRW · 2 Highest-Preference · 3 Lowest-Preference
```

Election order under Alg 2: **highest preference**, then **DP=1 beats DP=0**,
then **lowest Originating Router IP** (IPv4 sorts before IPv6 — which is what
Rust's `Ord for IpAddr` already does). Alg 3 is the same with the preference
comparison reversed. If any PE on the segment advertises a different
algorithm, the whole segment falls back to Alg 0 — `negotiate_df_alg()`
already implements that.

Because preference is a per-segment property and the same PE wins every tag,
the operator recipe for "PE1 active, PE2 standby across the board" is simply:
give every `ethernet-segment` on PE1 a higher preference than the
corresponding segment on PE2. RFC 9785 §4.2's per-tag local override (a
policy that re-carves tag ranges under a preference-signalled segment) is
explicitly **not** offered — it re-introduces exactly the per-VLAN split we
are removing, and an inconsistent override duplicates or drops frames.

### 3.4 Deltas required

1. **DP bit** — encode/decode `DfElectionEc::CAP_DONT_PREEMPT = 0x8000` and
   apply it in the tie-break in `pref_wins()` (`ethernet_segment.rs:259`),
   between preference and address. **Honouring a remote PE's DP bit is
   mandatory, not optional**: if a peer sets DP and we ignore it, the two
   sides rank the segment differently and both forward. The bit only changes
   an outcome once somebody sets it, so the existing FRR-matching comparison
   is untouched on a segment where nobody does. What *is* staged is our own
   advertisement: the first release advertises `DP=0` unless `dont-preempt`
   is configured, and the non-revertive operational-preference behaviour
   (item 5) lands after that.

   **The bit alone is not non-revertive operation, and no user-facing text
   may imply it is.** It ranks a PE ahead of one that does *not* set it; with
   the bit on every PE at equal preference — how an operator would normally
   configure it — the tie still falls through to the address, so the
   lowest-address PE reclaims the role on recovery. Pinning a DF across a
   recovery today means giving that PE the higher preference. (Caught in
   review of the phase-1 commit: the book, the YANG description and the
   config handler all promised the §4.3 behaviour; all three now state the
   tie-break and the limitation.)
2. **Default preference 32767** — RFC 9785: when the algorithm is selected
   and no value is configured, the advertised preference MUST be 32767.
   Today `df_election_ec()` (`ethernet_segment.rs:182`) only selects Alg 2
   when `df_preference` is `Some`, so "algorithm without a value" is not
   expressible. Add `algorithm {default|hrw|preference|lowest-preference}`
   and let `preference` be optional under it.

   **Precedence is a compatibility constraint, not a taste question.** Before
   the preference arms existed the leaf had only `default` and `hrw`, and a
   `preference` value selected Alg 2 over either — so those spellings must
   keep meaning Alg 2. A PE that changed algorithm across an upgrade would
   not merely differ from its not-yet-upgraded peers: it would fail the RFC
   8584 unanimity check and drop the **whole segment** to carving, moving the
   DF on a live service. Beside the two new arms a value selects which of
   them bids; `show` names the override where it applies. (Also caught in
   review of the phase-1 commit, which had the explicit leaf winning.)
3. **Preference `0` is legal** — the YANG range is `1..65535`; RFC 9785 uses
   the full `0..65535`. Widen it (a pure relaxation, no migration).
4. **Candidate type** — `DfCandidate` is the tuple `(IpAddr, u8, u16)`
   (`ethernet_segment.rs:252`). It must carry the capability bitmap too (DP
   now, T in §5). Turn it into a small struct
   `DfCandidate { addr, alg, pref, caps }`; `es_df_candidates()`
   (`route.rs:19751`) fills it from each Type-4's EC.
5. **Non-revertive (optional, phase 2 of the slice)** — RFC 9785 §4.3: a PE
   returning with DP configured advertises an *operational* `(Pref, DP)`
   inherited from the incumbent DF rather than its administrative one, so it
   does not preempt. This needs a per-segment `operational_pref` computed at
   the moment we (re)join a segment, i.e. in `evpn_originate_ethernet_seg()`
   and again whenever the candidate set changes. It is the one piece here
   with real state; it can ship after the rest.
6. **Alg 3 (Lowest-Preference)** — trivial once ranking is parameterized;
   include it so a mixed vendor segment configured "lowest" interoperates.

### 3.5 What preference does *not* give you

Preference makes the *election* deterministic. It does not make the
*candidate set* uniform, and the candidate set is what AC-DF narrows.

Take PE-A (pref 500), PE-B (300) and PE-C (100) on both ES-1 and ES-2. While
every member is eligible, A is DF and B is backup for every service on both
segments — the intended result. Now let A's ES-1 access circuit fail with
RFC 8584 AC-DF in effect: A drops out of ES-1's election only
(`ac_df_filter()`, `ethernet_segment.rs:502`), so B wins ES-1 while A keeps
ES-2. That is correct behaviour — it is the whole point of AC-DF — but it
means "PE-A is the active PE" is a statement about a healthy fabric, not an
invariant.

The same holds one level down: AC-DF narrows per `(EVI, tag)`, so a PE can
lose one bridge domain of a segment and keep the others. If a deployment
genuinely needs all-or-nothing takeover, that is the whole-PE fate-sharing
follow-up in §8, not a property of Alg 2.

Also unchanged by any of this: **all-active segments never use the role
signal**. Every attached PE is primary there, and the BUM DF elected for an
all-active segment must not be advertised as the sole unicast endpoint (§4.5).

## 4. Gap 2 — telling the ingress PE which PE is the DF

### 4.1 What we do today, and why it is not enough

`es_sa_primary()` (`route.rs:19170`) picks the group's primary as *the PE
with the most selected Type-2 routes carrying this ESI in this EVI*. It is a
decent inference — under single-active only the DF learns from the CE — but:

- **No MAC, no primary.** Before the CE has sourced anything, `primary` is
  `None` and `order_es_members()` leaves the lowest address first. On a
  service whose first frame is toward the CE, slot 0 may be the standby.
- **Stale MACs outlive the DF.** A DF change does not withdraw the old DF's
  Type-2s (they are still valid entries with an ESI); the count only flips
  once the new DF has learned as many MACs as the old one still advertises.
  Failover therefore waits on *MAC re-learning*, which is the slow path the
  ES nexthop group exists to avoid.
- **It cannot represent the backup.** There is a DF-or-not answer per PE;
  "second best" is address order, not election order.

Suppressing advertisements on the non-DF (the reviewer's first experiment)
fixes the ambiguity but makes every switch-over a full route convergence —
and collides with the per-ES A-D mass-withdraw semantics, where a withdrawal
means *the segment is gone*, not *my role changed*.

### 4.2 Signal the role: L2-Attr P/B on the E-LAN per-EVI A-D

`draft-ietf-bess-rfc7432bis-14` §7.11 extends the EVPN Layer-2 Attributes EC
(`0x06`/`0x04`) control flags and §7.11.1 states that P and B are the
per-`<ESI, EVI>` attributes carried on the **Ethernet A-D per EVI** route:

```
                    1 1 1 1 1 1
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    | MBZ           |RSV|RSV|F|C|P|B|      B = 0x0001   P = 0x0002
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+      C = 0x0004   F = 0x0008
```

`B`, `P`, `C` and the 2-octet MTU are already in `L2AttrEc`
(`ext_com.rs:412`) with exactly these values, because VPWS (RFC 8214 §3.1)
uses the same EC — and `VpwsRole` (`ethernet_segment.rs`) already maps
Primary / Backup / NonDesignated onto `(P, B)`. **The codec work is zero**;
what is new is attaching it to the *E-LAN* per-EVI A-D
(`evpn_originate_ethernet_ad_evi()`, `route.rs:18445`, which today carries
only the EVI RT, the encap EC and the service binding) and consuming it.

Roles advertised per `(ESI, EVI)`:

| Elected role | P | B | What a remote ingress PE does |
| ------------ | - | - | ----------------------------- |
| DF | 1 | 0 | forwarding member (cradle group slot 0) |
| Backup DF (runner-up of the same election) | 0 | 1 | installed, not forwarding (slot 1) |
| Other non-DF | 0 | 0 | installed, never promoted directly |

Both members stay in the group at all times; a role change is an
**attribute-only update** on a route that is already there, so the remote
re-orders one group — "activate/deactivate", exactly the property the
reviewer reported as the reason this approach switches fast. Nothing is
withdrawn, so nothing has to be re-advertised and re-selected.

`P=1,B=1` is rejected with a diagnostic (it is a VPWS-ism, meaningless here).
`F` is not used; we encode 0. MTU stays 0 on E-LAN A-Ds (no MTU check is
defined for E-LAN) — worth one interop check, since a peer that *does* check
would see 0 = "no check".

**Interop caveat, stated plainly:** rfc7432bis is an expired draft (rev 14,
2026-03-02) and, while it lists P/B as per-EVI A-D attributes, it does not
spell out the ingress selection procedure. The semantics in the table above
are *ours*. Therefore:

- The explicit mode is **config-gated** per segment (or per EVPN instance),
  default off in the first release.
- A remote PE that advertises no L2-Attr on its per-EVI A-D is `Unknown`,
  never "assumed DF"; a segment where no PE signals falls back to today's
  `es_sa_primary()` inference, unchanged.
- Re-check the draft's successor (and the bit assignments) before the codec
  is enabled by default.

### 4.3 Remote role state: `EvpnEsRemote`

Everything MH-related in zebra-rs today is recomputed by scanning the EVPN
Loc-RIB on a dirty flag (`vpws_df_drain()`, `route.rs:19021`). That is a good
property and this plan keeps it: **routes stay authoritative**. But two new
requirements need remembered state that no route carries —
*the incumbent* (for non-revertive preference, for conflict resolution, and
to avoid promoting a backup during first discovery) and *pending timers*
(§5) — and the reviewer hit the same wall in ZebOS and answered it with a
dedicated `evpn_sc_remote`. We take the same shape:

```rust
// bgp/ethernet_segment.rs — derived, rebuilt by the drain, never a 2nd RIB.
struct EsRemoteMember {
    pe: IpAddr,                 // Type-4 Originating IP / A-D next hop
    role: RemoteRole,           // Primary | Backup | NonDf | Unknown
    ad_es_live: bool,           // per-ES A-D present (mass-withdraw gate)
    ad_evi: bool,               // per-EVI A-D present for this bd
    member: EsNhgMember,        // the resolved forwarding endpoint
    stale: bool,                // retained under graceful restart (§9 risk 6)
    paths: Vec<PathRef>,        // provenance: (peer, RD, add-path id) — §4.4
}
struct EsRemoteBd {             // keyed (ESI, bd)
    members: BTreeMap<IpAddr, EsRemoteMember>,
    active: Option<IpAddr>,     // what we last programmed as slot 0
    backup: Option<IpAddr>,     // slot 1
    reason: SelectReason,       // signalled | inferred | incumbent | tie-break
    conflict: Option<String>,   // shown, not silently resolved
    generation: u64,            // §4.5 item 7
}
```

Selection per `(ESI, bd)`: the unique eligible `P=1` member is active; the
unique eligible `B=1` is slot 1; ties or duplicate `P=1` keep the **incumbent
`active`** if it is still eligible, else lowest address, and set `conflict`
(rendered by `show bgp evpn ethernet-segment` and logged once per change).
Eligibility is `ad_es_live && ad_evi && member resolves`. The output feeds
`evpn_es_nhg_sync()` (`route.rs:19061`) in place of `es_sa_primary()`; the
cradle-facing `Message::EsNhg` shape does not change — only the order does.

### 4.4 The two-RR problem

The reviewer's hardest debugging was remote DF synchronization "especially
with two RRs". Concretely, in this tree:

- **Identity.** The advertising PE is the Type-4 *Originating Router IP* /
  the A-D *next hop* — never the session peer. With RRs the session peer is
  the RR, and `ORIGINATOR_ID` is a third thing. `es_df_candidates()` already
  keys on the NLRI's `orig`; the new remote table must key on the same, and
  the A-D side must use `BgpNexthop::Evpn(..)` (as `evpn_es_nhg_sync()`
  does). Add a debug/show column naming the provenance so a mismatch is
  visible instead of mysterious.
- **Duplicate copies.** Each PE originates with its own RD
  (`<router-id>:<vni>` for per-EVI A-D, `<router-id>:0` for Type-4), so two
  PEs never collide; two RRs reflecting *the same* PE's route collide on the
  same `(RD, prefix)` and resolve by normal best-path — fine. The hazard is
  the reverse: RR-1 withdraws, RR-2 still holds a copy, so the prefix stays
  and the role does not change. Counting contributions (`paths`) and only
  dropping a member at zero is correct behaviour, not a workaround — but it
  makes "why is the old DF still primary" answerable from `show`.
- **Disagreeing copies.** Two RRs can hold different attribute versions of
  one PE's route (different P/B). BGP gives no cross-session ordering; we
  take the best path and, when the losing copy differs in role, record
  `conflict`. Explicitly: SCT (§5) is **not** a freshness/sequence number
  for P/B — do not use it as one.
- **No Type-4 at the ingress.** An ingress PE that is not on the segment
  does not import the ES-Import RT, so it has no Type-4s and cannot re-run
  the election. It must read the role off the per-EVI A-D alone. That is the
  whole reason the signal goes on the A-D and not the Type-4.
- **Every member must be visible as a path.** A backup that BGP never showed
  us cannot be pre-installed. Per-EVI A-Ds from different PEs carry different
  RDs (`<router-id>:<vni>`), so they are different prefixes and all are
  visible — verify that invariant explicitly on the test fabric rather than
  assuming it, and require ADD-PATH anywhere two PEs could share an RD.
- **The full set of change triggers.** The remote table is reconciled on:
  attribute-only updates, withdrawals, best-path changes, peer down, RT /
  import changes, ADD-PATH path removal, graceful-restart stale expiry, and
  the cradle reconnect replay (`RibRx::CradleUp`) — the last one rebuilds the
  derived table and re-tees every group, because the datapath forgot
  everything.

### 4.5 Invariants the role signal must not break

These are the traps that turn a correct election into a wrong forwarding
state; each becomes an assertion or a test in phase 3.

1. **Service identity is the VNI, not the Ethernet Tag.** The E-LAN per-EVI
   A-D carries `eth_tag = 0` with the VNI in the label field
   (`evpn_originate_ethernet_ad_evi()`, `route.rs:18445`), while the election
   runs with the VNI *as* the tag (`elan_df()`). Key the role by the EVI /
   bridge domain resolved from the attribute, never by the NLRI tag.
2. **A role update is attribute-only.** Re-originating the A-D with a new
   L2-Attr must preserve everything else on it: the EVI RT, the VXLAN
   encapsulation EC, the MPLS EVI label, the SRv6 DT2U Prefix-SID, the next
   hop and any policy-added communities. The route key must not move, or the
   remote sees a withdraw + announce and loses exactly the fast path this
   design exists to create.
3. **`P=1,B=1` is invalid here** — reject with a diagnostic rather than
   guessing. `P=0,B=0` means "on the segment, not selectable", and is never
   promoted directly.
4. **All-active is untouched.** No P/B on an all-active segment's A-Ds; the
   aliasing group keeps every member.
5. **Standby learning must not originate MAC mobility.** A single-active
   non-DF blocks in both directions, so it should not be learning from the CE
   at all — but if a stale or transient learn does occur, it must not be
   originated as a Type-2 with a bumped mobility sequence, or the real DF's
   entry loses to a MAC that is not reachable.
6. **The non-DF gate covers all four traffic classes, both directions** —
   known unicast, unknown unicast, broadcast and multicast, CE→core and
   core→CE (cradle `ES_DF_F_BLOCK` does this today; phase 5 re-proves it per
   class). Split horizon stays an independent filter: it is about where a
   frame came from, not about who is DF.
7. **One generation per endpoint switch.** When the active member changes,
   the group is re-teed as a unit with a monotonically increasing generation;
   a late completion from a superseded generation must not restore the old
   primary.
8. **Do not advertise `P=1` before forwarding is programmed.** Today
   `Message::EsNhg` / `EsRole` are fire-and-forget, so this ordering cannot be
   strictly enforced — §9 risk 4 decides whether cradle grows an ack or we
   document the window.

## 5. Gap 3 — RFC 9722 synchronized service carving

### 5.1 The window we are closing

Today: `startup-delay` makes a joining PE **withhold** its Type-4 and per-ES
A-D (`evpn_originate_es_routes()`, `route.rs:19410`) for N seconds, then
originate. The peers re-elect the moment the routes land. So the transition
instant is "whenever BGP happened to deliver", and the incumbent DF and the
new DF change roles independently — under single-active that is either a
loop (two DFs) or a black hole (none), for as long as the two events are
apart.

RFC 9722 replaces "wait, then announce" with "announce **when** we will
carve, then everyone carves together".

### 5.2 Wire format and procedure

```
    0                   1                   2                   3
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   | Type = 0x06   | Sub-Type(0x0F)|      Timestamp Seconds        ~
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   ~  Timestamp Seconds            |      Timestamp Fraction       |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

- **Service Carving Time (SCT) EC**, `0x06`/`0x0F`, carried on the **Type-4
  ES route**. 32-bit NTP seconds (prime epoch 1900-01-01 UTC) + the high 16
  bits of the NTP fraction (≈15 µs resolution); the low 16 fraction bits are
  zero on reconstruction.
- **T capability**, DF Election EC bitmap **bit 3 = `0x1000`**. Synchronized
  carving is used only if **every** PE on the segment signals `T=1`;
  otherwise all of them revert to the RFC 7432 timer behaviour.
- A joining/recovering PE advertises `SCT = now + peering-time` (RFC 7432
  §8.5 step 2's timer, default 3 s; larger values are encouraged where BGP
  propagation is slow) and carves at its own SCT.
- **Skew** (default **10 ms**): a PE that is *currently DF* and is losing the
  role transitions **DF→NDF at `SCT − skew`**; a PE gaining the role
  transitions **NDF→DF at `SCT`**. The asymmetry guarantees no overlap — we
  accept a ~10 ms gap rather than a 10 ms loop, which is the right trade on
  a bridged segment.
- Fallback rules: no SCT present ⇒ elect immediately (today's behaviour);
  SCT in the past, or further out than the local peering timer, ⇒ discard and
  elect immediately; any `T=0` peer ⇒ whole segment on timers.

### 5.3 How it lands in this tree

- **Codec**: `ExtCommunityValue::sct()/as_sct()` + an `SctEc { seconds,
  fraction }` with NTP↔`SystemTime` helpers (watch the 2036 era rollover —
  clamp and log rather than wrap silently).
- **Origination**: `evpn_originate_ethernet_seg()` (`route.rs:18329`) adds
  the SCT EC while a local carve is pending, and sets `T` in
  `df_election_ec()`.
- **Two mutually exclusive join behaviours.** Under RFC 9722 the Type-4 goes
  out **immediately, carrying the SCT** — the opposite of `startup-delay`,
  which withholds it. They cannot both be active on a segment: withholding
  the route hides the SCT that the mechanism depends on. Config must make
  `fast-recovery` and `startup-delay` exclusive (YANG `must`), and `show`
  must say which one is in force.
- **Timers**: the wire value is wall-clock; convert once, on receipt, into a
  monotonic `Instant` deadline (the codebase already schedules
  `Message::EsHoldExpired` with an `Instant` identity and ignores stale
  wake-ups — `route.rs:19683` — reuse that pattern verbatim for
  `EsCarveDue { esi, at }`). Store the pending carve on the segment; a newer
  valid SCT supersedes and cancels.
- **Election is unchanged.** RFC 9722 does not alter *who* wins — only
  *when* the answer is applied. Implementation-wise the verdict computed by
  `elan_df()` is staged, not applied, until the deadline; `evpn_es_df_sync()`
  gains "pending vs applied" per `(ESI, bd)` and only tees applied verdicts.
- **Failures are never delayed.** A local link-down / mass-withdraw closes
  the gate immediately; SCT delays only the *recovery* direction.
- **Clock trust.** We have no NTP-sync oracle in zebra-rs. First release:
  trust `SystemTime`, bound the accepted SCT window by the peering timer, and
  log every rejection. If the deployment needs more, a `clock-ready` gate can
  read chrony/timedatectl later — call it out rather than assume it.
- **Concurrent recovery.** Two PEs joining at once produce two SCTs. Keep one
  pending carve per segment, take the **latest valid** SCT, and recompute the
  staged verdict from the candidate set as it stands at the deadline — never
  run two carves for one segment, and cancel the superseded timer by its
  `Instant` identity.
- **Validation.** `skew` must be well under `peering-time` (reject at commit);
  an SCT in the past, or further out than `peering-time`, is discarded with a
  log line and the election runs immediately. Clock readiness and the last
  rejection reason belong in `show` (§7), not only in the log.

### 5.4 What SCT does *not* fix

SCT synchronizes the PEs **on the segment**. A remote ingress PE learns the
new primary from the §4 P/B update, which arrives on its own BGP schedule.
Recovery can still lose traffic for as long as that update takes; putting SCT
on the Type-1 to close that gap would be a protocol extension and is out of
scope. Say so in the release notes rather than claiming zero loss.

## 6. Configuration surface

```
router bgp <asn>
 afi-safi evpn
  ethernet-segment ES1
   esi 00:11:22:33:44:55:66:77:88:99
   redundancy-mode single-active
   interface bond0
   df-election
    algorithm preference          # ✅ default | hrw | preference | lowest-preference
    preference 200                # ✅ 0..65535; default 32767 under (lowest-)preference
    dont-preempt                  # ✅ empty; RFC 9785 D bit (non-revertive = phase 1b)
    ac-df                         # existing
    startup-delay 3               # existing; mutually exclusive with fast-recovery
    fast-recovery                 # presence container, RFC 9722
     peering-time 3               # seconds, default 3
     skew 10                      # milliseconds, default 10
   role-signaling l2-attr         # inferred (default) | l2-attr  — §4.2 gate
```

Notes:
- `algorithm` currently offers only `default|hrw`; `preference` is selected
  implicitly by setting the `preference` leaf. Keep that working (an existing
  config with only `preference` still means Alg 2) and add the enum arms.
- Widen `preference` to `0..65535`.
- `role-signaling` may end up per-EVPN-instance rather than per-segment —
  decide in phase 3; per-segment is proposed because that is the unit the
  operator upgrades.
- Adding BGP config paths trips `bgp_config_audit_tests`: regenerate with
  `ZEBRA_UPDATE_AUDIT_DOCS=1 cargo test -p zebra-rs bgp_config_audit`, and
  bump the `docs/orphan-report.txt` Total/Handled counts by hand.

## 7. Show / observability

- `show bgp evpn ethernet-segment` gains: negotiated algorithm **and
  capability bits** (`df-election:alg2+ac-df+dp+t`), our advertised
  `(pref, DP)` vs the administrative one when non-revertive is in play, the
  elected DF *and* backup DF per bd, and — when a carve is pending — the SCT
  deadline and remaining time.
- A new remote view (either a subsection of the above or
  `show bgp evpn ethernet-segment <esi> remote`): per `(bd, PE)` the role,
  P/B provenance (peer, RD, ADD-PATH id), per-ES/per-EVI liveness, stale/GR
  status, the selection reason (`signalled` / `inferred` / `incumbent` /
  `tie-break`), the programmed generation, and any `conflict` reason. This is
  the view that makes the two-RR case debuggable rather than archaeological.
- Under RFC 9722: clock readiness and the last rejected SCT (with the reason)
  are shown, not only logged.
- Log (info, `category = "evpn"`) every applied role transition with the
  reason (`pref`, `carve`, `ac-df`, `port-down`, `sct`), every rejected SCT,
  and every conflict onset/clear. Failover timing is then measurable from
  the daemon log without packet capture.

## 8. Phasing

Small slices, each independently mergeable and separately provable —
smallest first, per the standing preference.

**Status: phase 1 is implemented on `evpn-single-active`.** The DF Election EC
grew `CAP_DONT_PREEMPT` (`0x8000`) and `ALG_PREF_LOWEST` (Alg 3);
`DfCandidate` is a struct carrying the whole advertised capability bitmap;
`pref_wins()` ranks preference → DP → address, with the preference
comparison reversed under Alg 3; `df_election_ec()` bids RFC 9785's
mandatory 32767 default and advertises DP only under a preference algorithm;
YANG gained the `preference` / `lowest-preference` arms, the `dont-preempt`
leaf and a `0..65535` preference range, with a `preference` value still
overriding the pre-existing `default` / `hrw` arms so no configuration
changes what it advertises across an upgrade (§3.4 item 2). `show bgp evpn
ethernet-segment` renders each PE's bid and DP bit, names a segment that
fell back for disagreement, and carries the same in JSON. Proof: 10
`df_election*` codec tests, the `preference_ranks_pref_then_dp_then_address`
and `preference_defaults_to_the_rfc_9785_midpoint` unit tests, and three new
`bgp_evpn_es.feature` scenarios (preference beats address order; equal bids
fall to the lowest address; the DP bit alone moves the DF) — the last two
are a control/treatment pair, and removing the `dont-preempt` leaf from the
treatment config was verified to turn exactly that scenario red. A fourth
scenario pins the legacy precedence (`algorithm hrw` + `preference` still
advertises Alg 2), likewise verified by mutating the precedence back. Adjacent
features `bgp_evpn_vpws_multihoming`, `bgp_evpn_vpws_startup_delay`,
`bgp_evpn_vpws_vxlan_multihoming`, `bgp_evpn_df_election`,
`bgp_evpn_gateway_df` and `bgp_evpn_srv6_macip_multihoming` all still pass.
Not in phase 1, by design: the non-revertive operational preference
(item 5 of §3.4), which needs the incumbent state §4.3 introduces.

| Phase | Deliverable | Gate |
| ----- | ----------- | ---- |
| **1** ✅ | **RFC 9785 completion**: DP bit codec + tie-break, `DfCandidate` → struct with caps, Alg 3, default pref 32767, YANG `algorithm` arms + `0..65535` + `dont-preempt` | **Done** — see the status note below |
| **2** ✅ | **SCT codec + T bit** (no behaviour change): `SctEc`, NTP conversions, parse/emit/Display | **Done** — see the status note below |
| **3a** ✅ | **Origination**: `role-signaling l2-attr`, the elected role on the E-LAN per-EVI A-D, `show` | **Done** — see the status note below |
| **3b** | **Consumption**: `EsRemoteBd` + provenance, `evpn_es_nhg_sync()` selects on the signalled role, `es_sa_primary()` retained as the fallback, conflict in `show` | Unit: selection/conflict/eligibility table. BDD: backup promotion on per-ES A-D withdraw, two-RR duplicate-copy scenario |
| **4** | **RFC 9722 behaviour**: staged vs applied verdicts, `EsCarveDue` timer, skew, `fast-recovery` config, exclusivity with `startup-delay`, fallbacks | Unit with an injected clock: SCT accept/reject bounds, skew ordering, T=0 fallback, superseding SCT. BDD: joining PE does not become DF before its SCT; incumbent steps down first |
| **5** | **Datapath proof (cradle)**: primary switch on a P/B change alone, with the old DF's Type-2s still in the table; both traffic directions on the standby stay blocked | cradle BDD twin of `cradle_evpn_mh_sa_zebra` driven by a role change instead of a port-down; `l2_drop_nondf` / `l2_es_nhg` counters as the discriminator |
| **6** | **Docs + interop**: update `bgp-evpn-support-status.md` and the ES design doc, book chapter, CHANGELOG at the release cut; run interop-lab phases P1/P4 against FRR for the preference/DP tie-break | Lab report in `bgp-evpn-mh-frr-interop-report.md` |

**Status: phase 2 is implemented** on `evpn-sct-codec`. `ExtCommunityValue::
sct()/is_sct()/as_sct()` and `SctEc { seconds, fraction }` carry the RFC 9722
§2.1 Service Carving Time (`0x06`/`0x0F`), with `from_unix_micros` /
`to_unix_micros` / `from_system_time` / `to_system_time` doing the NTP
prime-epoch conversion; `DfElectionEc::CAP_TIME_SYNC` (`0x1000`) plus
`time_sync()` / `set_time_sync()` / `with_time_sync()` carry the T
capability, and both render in `Display` (`sct:<unix>.<micros>`,
`df-election:alg2:pref100+ac-df+dp+t`). Nothing advertises either yet —
**deliberately**: RFC 9722 gates synchronized carving on every PE signalling
T, so a PE that advertised the bit while ignoring SCT would be claiming a
behaviour it does not have. Phase 4 turns it on together with the
scheduling. Decoding is already live, because phase 1's `DfCandidate.caps`
keeps the whole advertised bitmap — a peer's T bit is retained and shown
today. Era handling is explicit: a seconds field below the prime-epoch
offset cannot be a real era-0 instant (it would predate 1970), so it reads
as era 1, which keeps the codec correct across the 2036-02-07 rollover
instead of jumping 136 years backwards. `SctEc`'s `Ord` is **chronological,
not the derived wire order**, for the same reason: §5.3 has this code take
the *latest valid* SCT, and `.max()` over raw 32-bit seconds picks the
earlier instant across the rollover (caught in review of the phase-2
commit). Proof: 4 SCT tests (wire layout
against the RFC figure, the 2208988800 epoch constant, the era-1 boundary in
both directions, the ~15.26 µs quantum with a 10 ms skew surviving it, and a
parse round trip) plus the T-bit position and its coexistence with AC-DF and
DP.

**Status: phase 3a is implemented** on `evpn-elan-role-signal`. Phase 3 is
split because origination and consumption fail differently: 3a only changes
what this PE *says*, behind a config gate, while 3b changes what a remote PE
*forwards*. 3a adds `RoleSignaling {Inferred, L2Attr}` (the
`ethernet-segment <name> role-signaling` leaf, default `inferred` =
unchanged behaviour), `elan_role()` beside `elan_df()` so the advertised bit
and the local BUM filter come from one election, the L2-Attr EC on
`evpn_originate_ethernet_ad_evi` for a single-active segment that signals,
and `evpn_reconcile_ad_evi_roles()` hooked into `vpws_df_drain` so a role
change is an attribute-only re-origination. It diffs against the bits
already in the Loc-RIB rather than a shadow copy, so a drain that changes
nothing advertises nothing. `show bgp evpn ethernet-segment` renders the
mode and the role per bridge domain, in text and JSON, alongside what was
last teed to the datapath.

One thing 3a had to fix rather than add (found in review): the
`redundancy-mode` handler re-originated the routes but never re-ran
`evpn_es_df_sync`, so the datapath kept the previous mode until some
unrelated BGP event happened to drain. That was invisible while nothing else
in the handler moved; with 3a updating the advertisement in the same edit it
becomes a divergence — all-active → single-active would advertise Backup
while the standby port still only filtered BUM, and the reverse would go on
blocking both directions with the P/B bits already gone. The handler now
marks the segment dirty and drains, which re-tees the gate and reconciles
the advertised role together. **The general shape: every ES config leaf that
feeds `Message::EsRole` must reach the drain, not just the origination
path.** Proof: three unit
tests (the role tracks `elan_df`; a holding or not-yet-elected PE advertises
*neither* bit, unlike `vpws_role`'s primary fallback; the keyword
round-trip) and a new `bgp_evpn_single_active.feature` — the DF advertises
P and its backup B, a preference change flips both PEs' bits on the route
they are already advertising, and with `role-signaling` back at its default
the EC disappears while the route stays.

Phases 1–2 are pure codec/config and can land in any order. Phase 3 is the
one that changes forwarding decisions on a remote PE; it is the one to gate
behind config. Phase 4 depends on 2. Phase 5 depends on 3.

### 8.1 Acceptance topology and measurements

One bench serves phases 3–5: **PE-A / PE-B / PE-C sharing two Ethernet
Segments**, a **remote ingress PE** on neither segment (so it holds no Type-4
and must read roles off the per-EVI A-D), and **two route reflectors whose
update delivery can be delayed independently**. Cases to cover:

- initial discovery; preference change; planned switchover; access-circuit
  failure on one segment only (§3.5); PE failure; recovery; two PEs recovering
  concurrently; asymmetric route delivery through the two RRs;
- missing P/B, invalid `P=1,B=1`, two PEs both claiming `P=1`, a role update
  arriving via one RR only, one RR failing while the other stays live;
- SCT in the past, SCT beyond the peering timer, a `T=0` peer joining, a clock
  step during a pending carve, graceful-restart stale expiry.

Measure, per case: loss duration, duplicate frames seen by the CE, number of
active-endpoint changes, any interval with two DFs or none, and convergence
from failure *detection* (not from the event). Pass = exactly one active
ingress endpoint at all times, no forwarding on a standby port, group failover
completing while the old DF's Type-2s are still in the table, and no DF
overlap across a synchronized recovery. Record the numbers in the phase-6
status update; release notes quote measurements, not adjectives.

Non-goals for this plan (explicit follow-ups): RFC 9786 port-active,
whole-PE fate sharing (all segments of a PE failing over together — needs a
health policy above the ES), ARP/ND synchronization on the standby PE,
and all-active behaviour, which is unchanged throughout.

## 9. Risks and open decisions

1. **DP interop.** `pref_wins()` currently matches FRR's comparison exactly.
   Adding the DP step is required for correctness (§3.4 item 1) and is inert
   until some PE sets the bit — but whether FRR ranks it the same way is
   unproven until interop-lab phases P1/P4. Ship the parse + tie-break +
   `show` first, advertise `DP=0` by default, and treat a mixed-vendor segment
   with DP set as unqualified until the lab says otherwise.
2. **rfc7432bis is expired.** §4.2's ingress procedure is our definition.
   Config-gated, off by default, re-checked against the successor draft.
3. **Clock trust for SCT.** No sync oracle today. Bounded acceptance +
   logging is the mitigation; a real readiness gate is a follow-up.
4. **No applied-state ack from cradle.** `Message::EsNhg`/`EsRole` are
   fire-and-forget, so "advertise P=1 only after forwarding is programmed"
   cannot be strictly honoured today. Phase 5 decides whether to add an ack
   to the cradle RPC or to accept the (small) window and document it.
5. **Does the user want port-active too?** If the deployment is really
   "standby port down", RFC 9786 is a better fit than single-active +
   preference and would reorder this plan.
6. **Graceful restart eligibility.** A member retained as stale across a
   restart still has routes, but its forwarding state is unknown. Decide —
   with evidence, in phase 3 — whether a stale member may stay `active`
   (route retention says yes; forwarding health may say no) rather than
   inheriting whatever falls out of the Loc-RIB.

## Appendix A — reviewer comments and responses

The comments that prompted this plan (verbatim, from the ZebOS-side
implementer):

> **(1) そもそも DF election に拡張が必要**
> ・RFC7432 だとあくまで DF election は modulus-based なので PE 単位だと DF/non-DF 共存する。恐らく利用者が想像する Single-active と違っているので、PE ごとに DF/non-DF を決めたい。以下 zebos で開発するにあたっての検討した内容。
> => RFC9786 Port-Active mode は一見それっぽいが、modulus-based で粒度を ES 単位にするので PE が2つ以上の ES を収容する場合は PE ごとに DF/non-DF を分けられない。
> => RFC9785 Preference-based mode で明示的に指定することで好きなように DF/non-DF を選択できるので、これを採用するのがよさそう
>
> **(2) Ingress が DF に投げる方法が RFC7432 には書いてない**
> ・non-DF が経路広告を抑制するようにしてみたが、切り替わりが時間かかりそうなので微妙
> ・rfc7432bis に L2 Attributes ecom で DF を広告するのを取り込むとあったので、DF bit 部分だけ実装してみた。両方持っといて activate/deactivate だけなので切替は簡単。backup path とは別に backup DF (best PE among non-DFs)への即時切替も動かせる。ただし remote DF 情報同期をとるのが(自分には)難しくて debug に時間がかかった。特に RR 2台構成になると面倒。
> ・RFC9722 の Service Carving Time ecom で timestamp を考慮するのがベストだが、そこまではまだ試せていない。
> ・remote DF 情報保持は既存の所で持てないかやろうとしたが、Backup DF の管理まで考えると微妙になったので evpn_sc_remote 構造体を別途用意してみた。
>
> **EVPN DF election sync (RFC 9722)**
> ・RFC7432 準拠だと link up 時に hold-time 秒(推奨3秒)待ってから DF election を行うが、冗長 PE は EAD/EVI を受け取ったら即時で DF election するので時差が生じる。
> ・特に Single-active だと DF 不在や DF 被りのタイミングが出来てパケロスしたりループ発生したりするのでこれを抑制する。
> ・EAD/EVI routes に SCT ecom によって DF election 実行時刻を付与して「せーの」で DF election する。
> ・DF かぶりを無くすために現在 DF ならほんの少しだけ早く DF election を行う工夫がある(skew)。
> ・hold-time によるパケロスは確かに減ったので single-active 対応するなら入れたい。

Point-by-point response:

| Comment | Response |
| ------- | -------- |
| Modulus election leaves DF/non-DF mixed within a PE | Agreed, and it is why §3 exists. `elan_df()` carves on the VNI today |
| RFC 9786 port-active does not separate DF per PE with ≥2 ES | Confirmed from RFC 9786 (bit 5, modulus over ESI bytes 3–6, `<ES>` scope). Not adopted as the answer; kept as a separate follow-up for standby-port semantics |
| RFC 9785 preference-based is the right mechanism | Adopted. Alg 2 already ships; §3.4 lists the five deltas (DP, default 32767, pref 0, capability-carrying candidates, Alg 3) |
| Non-DF advertisement suppression is too slow | Agreed; §4.1. It also overloads the mass-withdraw meaning of a per-ES A-D withdrawal |
| L2-Attr DF/role bit, both paths kept, activate/deactivate | Adopted as §4.2 — with the correction that the bis expresses this as the existing **P/B** pair on the per-EVI A-D rather than a new DF bit. Our `L2AttrEc` already encodes P/B/C/MTU, so this is origination + consumption, not codec work |
| Backup DF, distinct from backup path | Adopted: the backup DF is the election runner-up (`elect_forwarders()` already returns it) and is advertised `B=1`; the datapath already pre-installs non-slot-0 members, so the two notions stay distinct but composable |
| Remote DF state was hard, especially with two RRs | §4.3 + §4.4. Identity from Originating IP / A-D next hop (never the RR), contribution counting so one RR's withdrawal does not delete a live member, conflict recorded and shown rather than silently resolved |
| A separate `evpn_sc_remote` structure was easier | Same conclusion: `EsRemoteBd`/`EsRemoteMember`, derived and rebuilt by the existing dirty-flag drain, routes still authoritative |
| SCT is best; not tried yet | §5, phased after the codec. Note the correction: RFC 9722 puts the SCT EC on the **Type-4 ES route**, not on the EAD/EVI route, and gates it on the **T** capability bit (bitmap `0x1000`) being advertised by every PE |
| Skew so the current DF moves slightly earlier | Confirmed: DF→NDF at `SCT − skew`, NDF→DF at `SCT`, default skew 10 ms |
| Hold-time loss really did drop; want it for single-active | Included as phase 4, and made mutually exclusive with the existing `startup-delay`, which withholds the very route the SCT would ride on |

## Appendix B — wire reference

| Object | Type/Sub | Carried on | Fields we use |
| ------ | -------- | ---------- | ------------- |
| DF Election EC | `0x06`/`0x06` | Type-4 ES | DF Alg (5 bits), Bitmap `D=0x8000` `A=0x4000` `T=0x1000` (`PortMode=0x0400`, unused), Preference (last 2 octets) |
| ESI Label EC | `0x06`/`0x01` | per-ES A-D (MAX-ET) | Single-Active flag, ESI label (MPLS) |
| L2 Attributes EC | `0x06`/`0x04` | per-EVI A-D (E-LAN, new here; VPWS already) | `B=0x0001` `P=0x0002` (`C=0x0004`, `F=0x0008` unused), MTU=0 |
| Service Carving Time EC | `0x06`/`0x0F` | Type-4 ES | NTP seconds (4) + high-16 fraction (2), prime epoch 1900 |
| ES-Import RT | `0x06`/`0x02` | Type-4, per-ES A-D | auto-derived from `esi[1..7]` |

## Appendix C — what was folded in from `bgp-evpn-single-active.md`

The parallel design document reached the same protocol conclusions
independently (preference-based election, P/B on the per-EVI A-D, SCT on the
Type-4, a dedicated remote-state table). These items of its were additive and
now live here:

| From that document | Landed as |
| ------------------ | --------- |
| Acceptance scope: VXLAN + cradle + two RRs first, MPLS/SRv6 qualified by packet tests, all-active and VPWS preserved | §1.1 |
| "Election remains per ES and service" — an AC failure on one segment can flip that segment alone, so whole-PE takeover is not a preference property | §3.5 |
| Honouring remote DP is required for interop even while we advertise DP=0 | §3.4 item 1, §9 risk 1 |
| Service identity must not be read off the Type-1 Ethernet Tag (tag 0 vs the VNI) | §4.5 item 1 |
| Role updates must preserve MTU / control word / encap / labels / SIDs / RTs / communities | §4.5 item 2 |
| Reject `P=1,B=1`; never promote `P=0,B=0`; all-active must not reuse its BUM DF as the unicast primary | §4.5 items 3–4, §3.5 |
| Non-DF gate must cover every traffic class in both directions; split horizon stays independent; standby learning must not originate false mobility | §4.5 items 5–6 |
| One generation per endpoint switch; a completion barrier before advertising `P=1` | §4.5 items 7–8, §9 risk 4 |
| Richer provenance in the remote table: contributing `(peer, RD, add-path id)`, stale/GR flag, selection reason, programmed generation | §4.3, §7 |
| Change triggers: attribute-only update, withdraw, best-path change, peer loss, RT change, ADD-PATH removal, GR expiry, datapath reconnect | §4.4 |
| Path visibility: unique RDs or ADD-PATH, or the backup cannot be pre-installed | §4.4 |
| Concurrent recovery takes the latest valid SCT and runs one carve; `skew` < peering interval validated at commit | §5.3 |
| Acceptance bench (PE-A/B/C, two ES, remote ingress PE, two RRs with controllable delay) and the measurement list | §8.1 |
| Graceful-restart eligibility decided on forwarding health, not route retention alone | §9 risk 6 |

Not carried over: its `EvpnScRemote` naming (this tree already calls the
analogous VPWS state `VpwsRemote`, so the type here is `EsRemoteBd` /
`EsRemoteMember`), and its phase numbering (the six slices in §8 are sized to
this repository's PR conventions instead).
