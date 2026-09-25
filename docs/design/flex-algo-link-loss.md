# Flex-Algo link-loss constraint — design

> **Status:** reviewed (2026-09-25); all six §10 decisions settled, each taking the
> recommendation. PR 1 (D1) merged as #2414, with its review follow-up #2416; PR 2 (D2–D4, D7,
> IS-IS) implemented on branch `flex-algo-link-loss-isis`. Where the implementation settled a
> detail this document left open, the text below says so.
> **Parent docs:** [stamp-measured-loss.md](./stamp-measured-loss.md) (the measured loss this
> consumes), [review sequencing](../reviews/stamp-isis-ospf-2026-09-16.md) (Pattern C, "Flex-Algo
> link loss"), [flex-algo-roadmap.md](./flex-algo-roadmap.md),
> [ospf-flex-algo-recap.md](./ospf-flex-algo-recap.md) ("Multi-router FAD election — deferred")
> **Branch:** `flex-algo-link-loss-design`

---

## 1. Why / scope

zebra-rs now measures link loss and advertises it in all three IGPs (#2407–#2410). The consumer
that measurement was built for is the Flexible Algorithm link-loss constraint,
[draft-ietf-lsr-flex-algo-link-loss](https://datatracker.ietf.org/doc/draft-ietf-lsr-flex-algo-link-loss/):
a Flex-Algorithm Definition (FAD) that says "exclude every link whose loss exceeds X", so a
loss-sensitive service gets its own topology that routes around lossy links.

The research for this document found a prerequisite first. **zebra-rs does not select a winning
FAD** (§4). Each router computes every algorithm from its own local configuration, and nothing
implements RFC 9350 §5.3's rule that a router which cannot support the winning FAD must stop
participating. A constraint added to that model is only correct in a network where every router
is configured identically. Against any other FAD source — a Huawei router advertising the
loss constraint today — two routers compute different topologies for the same algorithm, which
is how Flex-Algo forwarding loops. So this design has two parts: winning-FAD selection with the
participation rule (D1), then the loss constraint on top (D2–D7).

In scope: IS-IS (winning-FAD selection in both IGPs). Out of scope, with reasons in §9: OSPF's
loss constraint until it has a code point, loss as a metric, RFC 9843's delay and bandwidth
constraints, Cisco's local anomaly alternatives.

## 2. What the specifications require

### draft-ietf-lsr-flex-algo-link-loss-00 (15 June 2026, Standards Track, WG adopted)

Authors from Huawei and Cisco. Content is identical to `draft-wang-…-05`; the rules have been
stable since `wang-00` (October 2023). No code points are assigned.

- **The sub-TLV** (§2.1 IS-IS, §2.2 OSPF), a FAD sub-TLV named Exclude Maximum Link Loss
  (FAEML): "Type: 252(TBA by IANA)", "Length: 3 octets", "Max Link Loss: 24-bit unsigned integer
  representing the maximum allowable loss percentage. Encoded with a resolution of 0.000003% per
  unit". OSPF's IANA section says only "Type: TBA".
- **At most once:** "The FAEML sub-TLV MUST appear at most once in the FAD Sub-TLV. If it
  appears more than once, the IS-IS FAD Sub-TLV MUST be ignored by the receiving node."
- **Which loss (IS-IS):** "compared with the link loss advertised in Sub-Sub-TLV 36 [RFC8570] of
  ASLA Sub-TLV [RFC9479]. If the L-Flag is set in the ASLA sub-TLV, the maximum link loss
  advertised in the FAEML sub-TLV MUST be compared with the link loss advertised by the sub-TLV 36
  of the TLV 22/222/23/223/141 … as defined in [RFC9479] Section 4.2."
- **Which loss (OSPF):** Sub-Sub-TLV 30 of the ASLA sub-TLV (RFC 9492), in the Extended Link LSA
  (OSPFv2) or E-Router-LSA (OSPFv3). There is no legacy path.
- **Pruning:** "If the link loss exceeds the maximum link loss advertised in the FAEML sub-TLV,
  the link MUST be excluded from the Flex-Algorithm topology. However, if a link does not
  advertise the link loss but the FAD contains the FAEML sub-TLV, the link MUST NOT be excluded."
  §3 appends this to RFC 9350 §13's pruning rules.
- **Stability** (§4, operational) is left to the advertiser: long collection intervals,
  averaging and normalisation, flap suppression. No receiver-side mechanism is defined.
- **The A bit** is not mentioned in any revision.

Three defects in the draft, worth raising with the working group (§12):

- It gives the cap as "50.331642% (0xFFFFFF * 0.000003)". 50.331642 % is RFC 8570's 2²⁴ − 2;
  0xFFFFFF × 0.000003 is 50.331645 %.
- It names sub-sub-TLV 30 for OSPFv3 as well. OSPFv3's link-loss code point is 16.
- Its OSPF sub-TLV has length 3 and no reserved octet, while RFC 9843's OSPF Exclude Maximum
  Delay sub-TLV has length 4 with a reserved octet first.

### RFC 9350 — what the constraint plugs into

- **§5.3, selection:** "Every router that is configured to participate in a particular
  Flex-Algorithm MUST select the Flex-Algorithm Definition based on the following ordered rules …
  1. … select the one(s) with the numerically greatest priority value. 2. If there are multiple …
  select the one that is originated from the router with the numerically greatest System-ID … or
  Router ID." The candidates are "the advertisements of the FAD in the area (including both locally
  generated advertisements and received advertisements)".
- **§5.3, participation:** "If a node is configured to participate in a particular Flexible
  Algorithm, but there is no valid Flex-Algorithm Definition available for it or the selected
  Flex-Algorithm Definition includes calculation-type, metric-type, constraint, flag, or sub-TLV
  that is not supported by the node, it MUST stop participating in such Flexible Algorithm. That
  implies that it MUST NOT announce participation … and it MUST remove any forwarding state
  associated with it."
- **§13, pruning:** exclude admin group, exclude SRLG, include-any, include-all, then "If the
  Flex-Algorithm Definition uses something other than the IGP metric … and such metric is not
  advertised for the particular link … such link MUST be pruned." The loss rule is appended.

### RFC 8570 §4.4 — the value being compared

"The basic unit is 0.000003%, where (2^24 - 2) is 50.331642%. This value is the highest
packet-loss percentage that can be expressed … measured values that are larger than the field
maximum SHOULD be encoded as the maximum value." It gives 0xFFFFFF no special meaning. It also
says the advertised loss "MUST be the packet loss from the local neighbor to the remote neighbor
(i.e., the forward-path loss)" — relevant to D5.

## 3. Commercial vendor survey

The sources are the vendors' newest published YANG models (YangModels/yang, Juniper/yang,
nokia/7x50_YangModels, aristanetworks/yang, Huawei/yang) and configuration guides. [D] marks a
source that was read; [I] marks an inference.

| Vendor | Link-loss FAD constraint | Syntax / units | Link with no loss advertised | A bit |
|---|---|---|---|---|
| Huawei VRP (YANG 8.21.10+, NE40E/NE8000/NE9000/ATN) | **Yes, IS-IS only** [D]. OSPF Flex-Algo participation is *forbidden* by a YANG `must` when the FAD carries it [D] | `exclude-max-link-loss` 1..16777215, raw 0.000003 % units [I] | Not documented; the draft Huawei co-authors says include [I] | Not used [I] |
| Cisco IOS XR 26.2.1 | No [D] | — | — | — |
| Cisco IOS XE 26.1.1 | No [D] | — | — | — |
| Juniper Junos / Evolved 25.4R1 | No [D] | — | — | — |
| Nokia SR OS 26.7, SR Linux 26.3 | No [D] | — | — | — |
| Arista EOS 4.36.2F | No [I] (OpenConfig model; TOIs behind login) | — | — | — |

- **Cisco solves the same problem locally, not in the FAD.**
  - `affinity flex-algo anomaly <names>` (IOS XR 7.8.1) advertises a chosen affinity when the
    router's own performance measurement flags a link anomalous.
  - `metric fallback anomaly loss {increment | multiplier | maximum}` (IOS XR 25.1.1, also IOS XE)
    penalises the IGP metric; `maximum` makes "all routers … exclude this link".
  - Both are advertiser-side decisions keyed on the loss A bit. They are the draft's rejected first
    alternative (a step function on the metric), not the FAEML.
- **RFC 9843 precedent** (Exclude Maximum Delay, Exclude Minimum Bandwidth): IOS XR 7.11.1, IS-IS
  only (`maximum-delay 1-10000000` µs, `minimum-bandwidth` kbit/s); a link without the attribute
  is not excluded. Nobody else ships them publicly; RFC 9843's shepherd write-up reports a Juniper
  IS-IS implementation [I].
- **Code points:** the IS-IS FAD sub-TLV registry (Expert Review) has 0–12 assigned; the OSPF one
  (IETF Review) has 1–12. Les Ginsberg objected on the LSR list to squatting on 252 and pointed at
  RFC 7370 early allocation, which has not been requested. Huawei's shipping code most likely
  sends 252 [I].

The survey decides the scope: IS-IS is the only protocol with a deployed peer (Huawei) and a code
point to interoperate on, and even that code point is provisional.

## 4. Where zebra-rs stands

- **No winning-FAD selection, in any IGP.** SPF always uses the local config entry:
  - IS-IS: `isis/rib.rs:1333` clones `top.flex_algo.config` into `graph_flex_algo`. Received FADs
    are cached in `peer_fad` (`isis/inst.rs:242`, filled at `isis/lsdb.rs:351`), but only `show`
    reads it.
  - OSPFv2 / OSPFv3: `build_spf_input` / `build_v3_spf_input` (`ospf/inst.rs:16063`, `14834`).
    Received FADs are not cached at all. The comment at `ospf/inst.rs:13157` says "no multi-router
    FAD election yet (matches IS-IS)".
  - The YANG description (`config.yang:1577`) promises participation "using a FAD learned from
    another node", which the code does not do.
- **The unsupported rule is not implemented.** Unknown FAD sub-TLVs are kept opaque and re-sent
  (`isis-packet/src/sub/cap.rs:571`, `ospf-packet/src/parser.rs:1435`,
  `ospf-packet/src/v3.rs:2239`), and nothing checks them. Several FAD elements are not
  supported, yet zebra-rs participates silently and wrongly:
  - **SRLG exclude:** advertised, never enforced (`isis/graph.rs:628`, `ospf/inst.rs:13158`); the
    per-link SRLG TLVs 138/139 are not even decoded.
  - **The M flag:** sent only. Nothing uses the Flex-Algo prefix metric.
  - **Metric-type 2 (TE default):** silently computed as the IGP metric (`isis/graph.rs:636`,
    `ospf/inst.rs:13154`).
  - **Calc-type:** always sent as 0, never checked on receive.
- **Constraints enforced today:** affinity only, via `flex_algo::constraint::link_passes_fad`
  (`flex_algo/constraint.rs:54`), called at `isis/graph.rs:739`, `ospf/inst.rs:13237`, `14738`.
- **Attribute sourcing is inconsistent.** IS-IS delay follows RFC 9479 §4.2 (`peer_min_delay`,
  `isis/flex_algo.rs:93`), but IS-IS affinity reads an X-bit-only cache with no zero-length-mask
  fallback and no L flag (`isis/lsdb.rs:398`). OSPF unified both on RFC 9492 through the
  `asla_readers!` macro (`ospf/flex_algo.rs:213`).
- **Link loss is already reachable.** The IS-IS sub-TLV 36 parses inline and inside an ASLA
  (`isis-packet/src/sub/neigh.rs:647`), and `graph_flex_algo` holds the neighbour entry
  (`isis/graph.rs:707`). OSPF's loss lives only in ASLAs; neither ASLA struct has a `link_loss()`
  accessor yet.
- **A loss change already re-runs SPF**, in both IGPs, because re-originating our own LSP/LSA
  schedules it.
- **Pre-existing issues found by the survey** are listed in §11.

## 5. Design

### D1 — Prerequisite: select the winning FAD, and stop participating when it is unsupported

Per algorithm and per IS-IS level (per OSPF area in the OSPF follow-up):

- **Candidates** are the FADs in the level's LSDB: every router's received FAD (the `peer_fad`
  cache, made per-level if it is not) plus our own, *if* we advertise one (`advertise-definition`).
  A locally configured but unadvertised definition is not a candidate: RFC 9350 counts
  advertisements.
- **The winner** is the numerically greatest priority, then the numerically greatest System-ID.
  Selection is deterministic over the LSDB, so every router in the level reaches the same answer.
- **SPF uses the winner.** Its metric-type and constraints come from the wire FAD, not from
  local config. Local config then means only two things: whether this router participates in
  the algorithm, and what it advertises when `advertise-definition` is set.
- **Stop participating** when there is no winner, or when the winner carries anything this build
  does not support: an unknown sub-TLV, a calc-type other than 0, an unsupported metric-type, an
  unsupported flag. With today's support that includes the SRLG exclude sub-TLV, the M flag and
  metric-type 2 (§4). Stopping means:
  - withdrawing this router's SR-Algorithm participation for the algorithm (and the SRv6
    locator's algorithm);
  - removing the algorithm's routes, labels and SIDs;
  - saying why in `show`.
- **Re-evaluate** whenever the LSDB's set of FADs changes (a FAD appears, changes or is purged),
  or the local config changes.

This makes today's silent wrongness explicit. A network that uses SRLG exclude, the M flag or
TE-default with zebra-rs routers in it currently computes a topology the other routers do not
compute; after D1 those routers stop participating instead, which is safe. Each of those
features can be implemented later, and implementing one simply removes it from the unsupported
list. §10 decision 1 asks for this change explicitly, because it alters behaviour on upgrade.

The FAEML sub-TLV is itself on the unsupported list until D2–D4 land. So D1 alone already makes
zebra-rs safe against a Huawei FAD carrying it: zebra-rs stops participating rather than looping.

### D2 — The FAEML sub-TLV: wire format and code point

- **IS-IS:** FAD sub-TLV, type **252** (the draft's placeholder, most likely what Huawei sends).
  Length 3, a 24-bit unsigned value in 0.000003 % units, no flags. The type code lives in one
  constant, documented as provisional: when IANA assigns one, a release changes it and the notes
  say so.
- **Duplicate:** more than one FAEML in a FAD makes the whole FAD invalid (the draft's MUST).
  Invalid FADs are not candidates in D1.
- **Malformed** (length ≠ 3): the FAD is a candidate, but an unsupported one, so every router
  configured for the algorithm stops participating. A router that cannot read the constraint must
  not compute with a guess of it. (An earlier draft of this bullet said "ignored", as for a
  duplicate; the implementation keeps D1's single rule for anything unreadable instead.)
- **Robustness:** the codec keeps an unparseable FAEML as `Unknown`, as it does other malformed
  sub-TLVs, so the FAD still round-trips on re-flood; D1 then treats it as unsupported.
- **Truncated:** a sub-TLV whose declared length runs past the end of the FAD — a FAEML among
  them — used to end the sub-TLV walk, and the rest of the FAD was dropped, so routers computed
  without the constraint. The FAD now keeps those bytes, re-floods them as received, and D1
  treats the definition as unsupported ("truncated definition"). Found by the isis-packet
  security review of PR 2; recorded in the crate's `AUDIT.md` (F2).
- **OSPF: not in this plan.** No code point, a length that disagrees with RFC 9843, and no
  deployed peer: Huawei forbids it. Until then an OSPF FAD carrying an unknown sub-TLV simply
  makes zebra-rs stop participating (D1's OSPF follow-up).

### D3 — Configuration

```
router isis {
  flex-algo 128 {
    advertise-definition true;
    metric-type igp;
    exclude-max-link-loss 5.0;      # percent: prune links whose loss exceeds this
  }
}
```

- **In percent,** `decimal64` with 6 fraction digits, 0 to 50.331642 — the same form as every
  loss setting from #2408 (`minimum-change`, `anomaly-threshold`). The raw-unit style Huawei
  uses (1..16777215) is the alternative; §10 decision 4.
- **The commit rejects** a value over 50.331642 or with more than six decimal places
  (`config::check`, as for the measured-loss leaves).
- **Rounded to nearest** RFC unit — the same rounding the measured loss is encoded with
  (`encode_loss`). A link measuring exactly the configured percentage then encodes to the same
  integer as the threshold, and is not pruned: "exceeds" means strictly greater, in both the
  operator's and the wire's terms.
- **Zero is allowed:** it prunes every link advertising any loss. It is legal on the wire, and it
  is a rule for loss-free links only. The book warns that measured loss at zero is one lost probe
  away from pruning.
- `show` prints the value both ways, percent and raw units, so a Huawei-configured FAD reads
  unambiguously.

### D4 — Pruning

Appended after RFC 9350 §13's rules 1–4, per directed edge `A → B`:

- **The value compared** is the loss **A** advertises for that link, selected for the Flex-Algo
  application: RFC 9479 §4.2 for IS-IS. The selection order is:
  1. an ASLA with the X bit set;
  2. otherwise a zero-length-mask ASLA;
  3. if the applicable ASLA sets the L flag, the inline sub-TLV 36;
  4. no applicable ASLA means no value.
- **For this router's own links**, the value is what we advertise:
  `te_metric_effective().loss`, static over measured, the same value neighbours see.
- **Pruned** if the value is strictly greater than the FAEML value. The comparison is of raw
  integers, so every router reaches the same answer.
- **Kept** if no value is advertised (the draft's MUST NOT). This differs from metric-type 1,
  where a missing delay *prunes* (RFC 9350 rule 5). IS-IS pseudonode edges carry no ASLA, so LAN
  segments are kept.
- **No special values.** 0xFFFFFF is compared as a number like any other (RFC 8570 gives it no
  meaning). Treating it as "no value" locally would disagree with any router comparing it
  numerically. The same codec comment that claims otherwise is fixed (§11).
- **The A bit is ignored** (D6).

The implementation generalises `peer_min_delay` into one attribute reader,
`peer_link_attr(entry, pick)`, over the existing `applicable_aslas`, with delay and loss as two
picks. §10 decision 6 proposes moving IS-IS affinity onto it too. Selecting affinity by one rule
and loss by another is the same kind of inconsistency this design exists to remove.
As built: the IS-IS pruning check takes a `LinkAttrs { affinity, loss }` struct, read for every
edge from that edge's own reach entry through the RFC 9479 reader — this router's own edges
included, from its own LSP. That refines the "our own links" bullet above: the entry carries
exactly the static-over-measured value we advertise, and reading it per entry keeps parallel links
to one neighbour apart, which a lookup by neighbour through the interfaces could not (PR 2 review:
parallel links of 0 % and 10 % against a 5 % maximum were both pruned locally, while every other
router kept the clean one). The edge's forwarding identity needs the same care: each of our own
entries is paired with the interface that produced it — among the unused interfaces adjacent to
its neighbour, the one whose metric and attributes match the entry — so a surviving parallel edge
leaves by its own interface, not its pruned twin's (second review finding), and its metric-type 1
delay is that interface's. `link_prune_reason` returns why a link is pruned, so the graph and its `show` view
share one decision. OSPF's `link_passes_fad` keeps its signature (affinity only; OSPF has no loss
constraint). The per-peer affinity cache the LSDB rebuild used to fill, which read X-bit ASLAs
only, is gone: affinity is read from the reach entry at graph time, like delay and loss.

### D5 — Stability belongs to the advertiser, never the receiver

A link whose loss hovers around the threshold would flap in and out of the algorithm's
topology. The draft's §4 answers that on the advertising side, and so does this design.

**No receiver-side hysteresis, hold-down or damping on pruning. Ever.** Pruning must be a pure
function of the LSDB, or two routers that saw the same advertisements at different times prune
differently, and Flex-Algo loops.

The advertiser side already exists (measured-loss D6):

- re-advertisement at most once per loss interval;
- a change must exceed `max(threshold %, minimum-change)`;
- trust gates (a full window, integrity);
- withdrawal on silence, rather than advertising the cap.

Each re-advertisement costs one LSP flood and one SPF per router, at most once per loss interval
per link.

Operational guidance for the book:

- **Keep the threshold well above the measurement's resolution.** At the default 1 s probes over
  a 120 s window one probe is 0.83 %, so a 1 % threshold is two lost probes. Raise the probe rate
  or the loss interval (the draft suggests ten minutes) for tight thresholds.
- **Round-trip loss overstates forward loss.** By default zebra-rs advertises round-trip loss
  (measured-loss D3), so a link lossy only in the reverse direction can be pruned for its forward
  traffic. Where the constraint matters, configure both ends for direction: `reflector stateful`
  on one, `peer-reflector stateful` on the other.

### D6 — The A bit, and Cisco's local alternatives

- **The A bit plays no part in pruning.** The draft does not mention it, and comparing the value
  is already deterministic.
- **Cisco's local alternatives are out of scope** (§9), but they suggest a follow-up that fits
  zebra-rs well. Both `affinity flex-algo anomaly` and `metric fallback anomaly loss` key on the
  router's own A bit, which zebra-rs now computes (measured-loss D7).

### D7 — Show and observability

- `show isis flex-algo` shows:
  - the winning FAD per algorithm and level;
  - its originator;
  - whether this router participates and, if not, why (for example "not participating: unsupported
    FAD sub-TLV 252 from 0000.0000.0002");
  - `exclude max-link-loss 5.000000% (1666667)` when present. As built: the selection line
    shows the winner's wire value, `max link loss 5.000001% (1666667)`, and the local row the
    configured one, `max-link-loss=5.000000%(1666667)`.
- `show isis flex-algo <n> graph` marks links pruned by loss, with the value that pruned them.
  As built: a `Pruned links:` list of every pruned edge and its reason, affinity included.
- `show isis database` renders the FAEML sub-TLV instead of an unknown one.

## 6. Code points

| Item | IS-IS | OSPFv2 / OSPFv3 |
|---|---|---|
| FAEML FAD sub-TLV | 252, provisional (draft placeholder; not IANA-assigned) | not implemented (TBA) |
| Link loss compared | sub-sub-TLV 36 in the ASLA (RFC 9479), inline sub-TLV 36 of TLV 22/222 when the L flag says so | sub-sub-TLV 30 (v2) / 16 (v3) in the ASLA (RFC 9492) — follow-up |

## 7. Testing

- **Unit, each mutation-verified:**
  - D1 selection:
    - priority, then System-ID tie-break;
    - our own advertised FAD competing with received ones;
    - an unadvertised local definition is not a candidate;
    - a FAD purge changes the winner.
  - D1 participation:
    - every unsupported case stops participation (unknown sub-TLV, calc-type, metric-type 2,
      the M flag, SRLG exclude);
    - no FAD at all stops it too;
    - stopping withdraws the SR-Algorithm participation and removes the algorithm's routes;
    - a supported winner resumes it.
  - D2 codec: round trip, duplicate FAEML invalidates the FAD, length ≠ 3 does too, unknown
    preserved.
  - D3: rounding to nearest, the commit check, percent/units display.
  - D4, the pruning truth table:
    - loss above, equal and below the threshold;
    - no loss advertised;
    - X-bit ASLA, zero-length-mask ASLA, L-flag legacy;
    - the pseudonode edge;
    - our own link, static over measured;
    - 0xFFFFFF compared numerically.
- **BDD:**
  1. **FAD selection** — two routers advertise different definitions for algorithm 128; every
     router computes with the higher-priority one. Changing priorities moves the winner.
  2. **Unsupported FAD** — a router advertises a FAD this build cannot support (SRLG exclude will
     do; it is unsupported today); every zebra-rs router stops participating and withdraws the
     algorithm's routes.
  3. **Loss pruning** — a ring where algorithm 128 carries `exclude-max-link-loss 5`. The ring
     uses the stamp_loss BDD's nftables drops:
     - dropping every 10th probe on the preferred link moves algorithm 128's path off it, while
       algorithm 0 stays;
     - removing the drop brings it back once the measured loss falls under the threshold.

     The negative check (algorithm 0 unchanged) is mutation-tested for vacuity.

## 8. Delivery — smallest PR first

1. **Winning-FAD selection and participation, IS-IS** (D1): selection, the unsupported list,
   withdrawing participation, show. The FAEML is still unsupported, which already makes zebra-rs
   safe against Huawei FADs. BDD 1 and 2.
2. **The FAEML constraint, IS-IS** (D2–D4, D7): codec, config, pruning through the generalised
   attribute reader, show. It moves off the unsupported list. BDD 3.
3. **Winning-FAD selection, OSPFv2 and OSPFv3** (D1's follow-up). It includes the runtime
   config fix from §11, without which no FAD change reaches OSPF SPF at all.
4. **OSPF FAEML** — only once IANA assigns a code point and the length question is settled.

Then documentation: the book's Flex-Algo chapters, the supported-RFC appendix, and the review
sequencing's Pattern C entry.

## 9. Out of scope, and why

- **Loss as a metric** (the draft's rejected first alternative, a step function on the link
  cost). Not specified by any document, and would change metric-type semantics.
- **Cisco's local alternatives** (`affinity flex-algo anomaly`, `metric fallback anomaly loss`).
  Vendor-specific, advertiser-side policy. A natural follow-up, not part of the draft (D6).
- **RFC 9843's Exclude Maximum Delay and Exclude Minimum Bandwidth.** The same shape as FAEML,
  and cheap once D1 and the generalised attribute reader exist. Until implemented they are on D1's
  unsupported list, so a Cisco IOS XR FAD using `maximum-delay` makes zebra-rs stop participating,
  which is correct.
- **SRLG enforcement, the Flex-Algo prefix metric (M flag), metric-type TE-default.** Each is
  unsupported today and moves off D1's list when implemented.
- **OSPF FAEML** (D2).
- **BGP-LS export of FADs.** zebra-rs does not export FADs to BGP-LS today.

## 10. Decisions for the reviewer

The recommendation is listed first in each. **All six were decided on 2026-09-25, each taking the
recommendation.**

1. **Make winning-FAD selection and the unsupported rule a prerequisite (D1, PR 1)**, including
   the behaviour change on upgrade. **Decided 2026-09-25: yes.** The upgrade note in the release
   CHANGELOG must list the cases in which a zebra-rs router now stops participating. Routers stop participating where no FAD is advertised, or
   where the winner uses SRLG exclude, the M flag, TE-default or a non-zero calc-type — cases in
   which they currently compute a topology no other router computes. The alternative, the
   constraint on local config alone, is correct only when every router in the level is a
   zebra-rs router configured identically.
2. **IS-IS code point 252, marked provisional.** **Decided 2026-09-25: yes.** The alternative is
   to wait for an RFC 7370 early allocation, which nobody has requested. The risk is a
   renumbering release later; the constant stays in one place for that.
3. **Defer OSPF's FAEML** until a code point exists and the length question is settled.
   **Decided 2026-09-25: yes.** Huawei, the one implementation, forbids it on OSPF too. OSPF
   still gets D1's selection and unsupported rule (PR 3), so an OSPF FAD carrying the FAEML makes
   zebra-rs stop participating rather than compute without it.
4. **Configure the threshold in percent, rounded to nearest RFC unit**, like every other loss
   setting. **Decided 2026-09-25: yes.** The alternative was raw units, as Huawei does; `show`
   prints both.
5. **Ignore the A bit in pruning.** **Decided 2026-09-25: yes.** The draft is silent; comparing
   the value is deterministic.
6. **Move IS-IS affinity onto the same RFC 9479 attribute reader** as delay and loss, in PR 2's
   refactor. **Decided 2026-09-25: yes.** One selection rule for every Flex-Algo attribute. It
   changes which ASLA IS-IS affinity is read from (zero-length mask fallback, L flag), so PR 2's
   tests cover affinity sourcing as well as loss.

## 11. Pre-existing issues found by the survey

These are independent of the constraint, and listed so they are not lost:

- **OSPF runtime FAD changes do not take effect.** `commit_flex_algo_tables`
  (`ospf/inst.rs:1277`) commits the config tables but neither re-originates the Router
  Information / SR-info LSA nor schedules SPF. A FAD edit waits for an unrelated event. It is
  folded into PR 3.
- **OSPF FAD codec robustness.** In OSPFv2, a malformed *known* FAD sub-TLV ends the sub-TLV loop
  and drops the rest (`ospf-packet/src/parser.rs:1367`). In OSPFv3 it fails the whole FAD
  (`v3.rs:2305`). IS-IS keeps such a sub-TLV opaque. Fix in PR 3.
- **IS-IS codec comment** (`isis-packet/src/sub/neigh.rs:652`): "The reserved value 0xFFFFFF marks
  the metric as unavailable" is not in RFC 8570. Fixed in PR 2 (it matters to D4).
- **IS-IS Flex-Algo graphs walk TLV 22 only** (`isis/graph.rs:703`), not the multi-topology
  TLV 222.
- **Stale documents:** `flex-algo-roadmap.md:295-308` and `ospf-flex-algo-recap.md:122-123` still
  describe the delay metric and the participation cache as not implemented. There is also a stale
  comment at `isis/graph.rs:743`.

## 12. Feedback for the working group

For the LSR list, when this is implemented:

- the cap's arithmetic (50.331642 % is 2²⁴ − 2, not 0xFFFFFF);
- OSPFv3's link-loss code point is 16, not 30;
- the OSPF sub-TLV's length 3, against RFC 9843's length 4 with a reserved octet;
- a request for early allocation (RFC 7370), so implementations stop depending on 252.

## Sources

- [draft-ietf-lsr-flex-algo-link-loss-00](https://datatracker.ietf.org/doc/draft-ietf-lsr-flex-algo-link-loss/)
  and its adoption call on the [LSR list](https://mailarchive.ietf.org/arch/msg/lsr/djtzV8Q_O3vEga4esjJLEeBl8mI/);
  Les Ginsberg on code point 252: [LSR list](https://mailarchive.ietf.org/arch/msg/lsr/5xoRxrAYLeoeNiUX3ejvx7A2ncc/)
- [RFC 9350](https://www.rfc-editor.org/rfc/rfc9350.html) §5.3, §13;
  [RFC 8570](https://www.rfc-editor.org/rfc/rfc8570.html) §4.4;
  [RFC 9479](https://www.rfc-editor.org/rfc/rfc9479.html) §4.2;
  [RFC 9492](https://www.rfc-editor.org/rfc/rfc9492.html); [RFC 9843](https://www.rfc-editor.org/rfc/rfc9843.html);
  [RFC 9843 shepherd write-up](https://datatracker.ietf.org/doc/draft-ietf-lsr-flex-algo-bw-con/shepherdwriteup/)
- IANA registries: [IS-IS TLV codepoints](https://www.iana.org/assignments/isis-tlv-codepoints/),
  [OSPF parameters](https://www.iana.org/assignments/ospf-parameters/)
- Cisco: YangModels/yang `vendor/cisco/xr/2621/Cisco-IOS-XR-um-router-isis-cfg.yang`,
  `Cisco-IOS-XR-clns-isis-oper-sub1.yang`, `Cisco-IOS-XR-um-router-ospf-cfg.yang`;
  `vendor/cisco/xe/2611/Cisco-IOS-XE-isis.yang`, `Cisco-IOS-XE-ospf.yang`;
  [NCS5500 26xx Flex-Algo guide](https://www.cisco.com/c/en/us/td/docs/iosxr/ncs5500/segment-routing/26xx/configuration/guide/b-segment-routing-cg-ncs5500-26xx/enabling-segment-routing-flexible-algorithm.html);
  [NCS540 25xx Flex-Algo guide](https://www.cisco.com/c/en/us/td/docs/iosxr/ncs5xx/segment-routing/25xx/b-segment-routing-cg-25xx-ncs540/enabling-segment-routing-flexible-algorithm.html);
  [IS-IS penalty for link loss anomaly](https://www.cisco.com/c/en/us/td/docs/iosxr/cisco8000/is-is/isis-config-guide-cisco8000/is-is-protection-and-resiliency-enhancements-w/is-is-penalty-for-link-loss-anomaly.html)
- Juniper: Juniper/yang `25.4/25.4R1{,-EVO}` `junos-conf-routing-options@2025-01-01.yang`;
  [IS-IS User Guide](https://www.juniper.net/documentation/us/en/software/junos/is-is/is-is.pdf)
- Nokia: nokia/7x50_YangModels `latest_sros_26.7/nokia-combined/nokia-conf.yang`;
  [SR Linux 26.3 Flex-Algo](https://documentation.nokia.com/srlinux/26-3/books/segment-routing/flex-algorithm-isis.html)
- Arista: aristanetworks/yang `EOS-4.36.2F/openconfig/public/release/models/flex-algo/openconfig-flexalgo.yang`
- Huawei: Huawei/yang `network-router/8.21.10/ne40e-x8x16/huawei-flex-algo.yang`
  (`exclude-max-link-loss`), `8.22.0` `huawei-ospfv2-sr.yang` (the OSPF `must`)
