# Measured link loss for STAMP-driven TE metrics — design

> **Status:** implemented (2026-09-25) in the four PRs of §8: #2407 (accounting), #2408
> (advertisement), #2409 (Anomalous bit), #2410 (direction). All four §10 decisions settled;
> design review round 1's six findings resolved (§11). Each PR's own review findings are
> recorded in the section they changed.
> **Parent docs:** [stamp-isis-ospf.md](./stamp-isis-ospf.md) (the STAMP → IGP integration
> this completes), [review sequencing](../reviews/stamp-isis-ospf-2026-09-16.md), step 4 "Measured loss"
> **Branch:** `stamp-measured-loss`

---

## 1. Why / scope

Every RFC 8570 / RFC 7471 performance sub-TLV that zebra-rs can advertise is now measured
except one: **unidirectional link loss**. Delay, min/max delay and delay variation come from
the STAMP session on each point-to-point link, carry per-value Anomalous bits, and reach
IS-IS, OSPFv2, OSPFv3 and BGP-LS. Loss can only be configured statically.

The raw material already exists. Every STAMP session counts the probes it sends and the
replies it gets back (`StatsWindow::record_sent` / `record_delay`,
[stats.rs](../../zebra-rs/src/stamp/stats.rs)), and `show stamp` prints a per-window loss
percentage. It is deliberately kept out of the IGP export, and for good reason: at the
default one probe per second, a 30-second window has 30 samples, so one lost probe reads as
3.3 % loss and the value would re-flood an LSP for every stray drop.

This document settles how to turn probe counts into an advertisable loss value. It is based
on what the RFCs require (§2), what commercial implementations actually ship (§3), and the
shape of the existing code (§4).

**In scope:** measured loss on the existing STAMP sessions, advertised in IS-IS sub-TLV 36,
OSPFv2 sub-TLV 30 and OSPFv3 sub-TLV 16, with its Anomalous bit. BGP-LS TLV 1117 follows
automatically through the existing translation.

**Out of scope:** consumers of the value (Flex-Algo loss constraints, an IGP metric penalty
on a loss anomaly), counter-based "direct mode" loss, and LAN circuits. §9 explains each.

## 2. What the RFCs require

[RFC 8570 §4.4](https://www.rfc-editor.org/rfc/rfc8570.html#section-4.4) (IS-IS sub-TLV 36;
RFC 7471 §4.4 is the OSPF twin, sub-TLV 30; OSPFv3 uses the Extended-LSA code point 16):

- "Link Loss: This 24-bit field carries link packet loss as a percentage of the total traffic
  sent over a configurable interval."
- "The basic unit is 0.000003%, where (2^24 - 2) is 50.331642%." Larger measured values
  "SHOULD be encoded as the maximum value."
- "The A bit is set when the measured value of this parameter exceeds its configured maximum
  threshold."

[RFC 8570 §5–§7](https://www.rfc-editor.org/rfc/rfc8570.html#section-5), which govern every
performance sub-TLV:

- Values "MUST represent an average over a period of time" (min/max delay and residual
  bandwidth excepted). Loss is not excepted.
- "The measurement interval, any filter coefficients, and any advertisement intervals MUST be
  configurable per sub-TLV." **Loss therefore needs its own knobs, not delay's.**
- Implementations "SHOULD provide configurable accelerated advertisement thresholds per
  sub-TLV".
- "The A bit is cleared when the sub-TLV's performance has been below (or re-crosses) this
  threshold for one or more advertisement intervals."
- Implementations "SHOULD suppress sub-TLV re-advertisement and/or lengthen the period", and
  "Only the accelerated advertisement threshold mechanism … may shorten the re-advertisement
  interval."
- "default measurement interval for all sub-TLVs SHOULD be 30 seconds"; the default
  announcement periodicity "SHOULD be set to 120 seconds".

[RFC 8762 §4](https://www.rfc-editor.org/rfc/rfc8762.html#section-4) (STAMP) defines two
Session-Reflector modes, and the difference decides whether loss can be split by direction:

- Stateless: the reflector "does not maintain test state and will use the value in the
  Sequence Number field in the received packet as the value for the Sequence Number field in
  the reflected packet."
- Stateful: the reflector "maintains the test state, thus allowing the Session-Sender to
  determine directionality of loss using the combination of gaps recognized in the Session
  Sender Sequence Number and Sequence Number fields". "As a result, both near-end (forward)
  and far-end (backward) packet loss can be computed."
- Either way, the reflected packet's "Session-Sender Sequence Number … fields are copies of
  the corresponding fields in the STAMP-Test packet".

[RFC 7680](https://www.rfc-editor.org/rfc/rfc7680.html) (the IPPM one-way loss metric)
defines a packet as lost when it has not arrived within a waiting time *Tmax*. That is the
definition §5 D2 adopts.

## 3. Commercial vendor survey

Sources are listed at the end. Where a vendor's documentation could not be read directly,
the finding is taken from its published YANG models, which carry exact leaf names and ranges.

| Vendor | Dynamic link loss into the IGP? | How it is measured | Windows / defaults | Suppression | Anomaly |
|---|---|---|---|---|---|
| **Cisco IOS XR** | Yes | Two sources. The delay profile's own TWAMP-Light/STAMP probes yield *synthetic* loss (YANG revision 2023-10-26: "Add packet anomaly loss config for delay profiles"). Interface loss-measurement sessions keep TX/RX packet counters per window. | Probe `computation-interval` 1–3600 s (docs: default 30 s). Periodic advertisement `interval` 30–3600 s, described as the "Periodic advertisement **and metric aggregation** interval" (docs: default 120 s). Oper model keeps a **probe-window** loss, a **periodic-window** loss and a **rolling average**. | Periodic `threshold` (% change vs last advertisement) + `minimum-change`. Separate `accelerated` threshold. | `anomaly-loss upper-bound` 1–99 %, `lower-bound` 0–98 %. The A bit is set above the upper bound and cleared below the lower one. Since 25.1.1, IS-IS can add a metric penalty while it is set (`metric fallback anomaly loss increment 500`; increment, maximum or multiplier). |
| **Cisco IOS XE 17** | Yes (IS-IS only) | Counter-based: "Simple Two-Way Direct Loss Measurement (SDLM) over IP with UDP", using dual-colour GRE marking. Limited to point-to-point GRE-IPsec tunnels. | `periodic interval 120` s. | `threshold 15%`, `minimum-change 0.2` (show output). | `anomaly-check lower-bound 0.5%`, `upper-bound 5.0%`. |
| **Huawei NE40E / NE5000E** | Yes (IS-IS) | `metric-link-loss advertisement enable`. Dynamic from TWAMP Light, or static. Only the IS-IS interface bound to a TWAMP Light session advertises, and only "when TWAMP Light measures valid statistics". **P2P only.** Reported onward through BGP-LS. | Timer tied to the TWAMP Light statistics interval. | `metric-link-loss suppress timer … percent-threshold … absolute-threshold …` (defaults not published in a readable form). | Not documented. |
| **Juniper Junos / Evolved** | **No** — delay only | TWAMP Light IGP delay measurement since 21.1R1. Unidirectional *drop* counts exist for STAMP stateful reflection, but only as monitoring, not IGP advertisement. | Per-cycle `probe-count` / `probe-interval`. Periodic advertisement 120 s. | Periodic threshold 10 %, accelerated advertisement. | — |
| **Nokia SR OS 26.7** | **No** — delay only | STAMP (default) or TWAMP Light link measurement. No loss leaf anywhere in `link-measurement`. | `interval` 1 s. `sample-window multiplier` 10 (10 s). `aggregate-sample-window multiplier` 12 (**120 s**). **`window-integrity`** % required before a window may report. | `threshold relative` % and `absolute` µs, per window. | — |
| **Arista EOS** | **No** found | TWAMP Light dynamic delay: average, min/max and variation; only min/max goes into the ASLA. | — | — | — |

What the implementations that do advertise loss agree on, and what zebra-rs should copy:

1. **The two vendors that advertise loss disagree on the default.** Huawei needs an explicit
   `metric-link-loss advertisement enable`. Cisco IOS XR's interface delay profile has **no
   loss switch at all** in the 26.2.1 config model: loss rides with delay measurement, and
   only its `anomaly-loss` bounds are configurable. No Cisco document states outright that
   IS-IS then advertises sub-TLV 36 by default, but the model leaves no way to measure delay
   without it. zebra-rs follows Cisco — on wherever measurement is on, with a per-link off
   switch (D10, §10 decision 4).
2. **Two windows: a short computation window and a 120-second advertisement window.**
   Cisco's 30 s / 120 s probe and periodic windows, Nokia's 12 × 10 s aggregate, and RFC 8570
   §7's 30 s / 120 s defaults all have this shape (D4).
3. **Two suppression knobs: a relative threshold and an absolute minimum change.** Cisco XR,
   Cisco XE and Huawei all use this pair, and Nokia uses the same pair for delay (D6).
4. **The Anomalous bit uses upper and lower bounds in percent** — Cisco XR and XE. That is the
   hysteresis zebra-rs already implements for delay (D7).
5. **A window must be complete enough to count.** Nokia's `window-integrity` and Huawei's
   "valid statistics" both refuse to report from a thin window (D5).
6. **P2P only.** Huawei says so explicitly, and every Cisco example is a point-to-point link or
   tunnel. zebra-rs already measures only P2P circuits.
7. **Acting on the anomaly is a separate feature.** Cisco's metric penalty arrived in 25.1.1,
   years after loss advertisement, and lives in IS-IS configuration, not PM (§9).
8. **Reflectors copy the sequence number by default.** Cisco's TWAMP Light reflector "simply
   copies the Sequence Number of the received packet", with no option to do otherwise.
   Juniper's does the same unless `stateful-sequence` is configured on the TWAMP Light or
   managed server (Junos OS Evolved 23.4R1), which makes it "generate the sequence number in
   the reflected payload independently" from a per-client cache. Juniper's sender then infers
   per-direction drops from those numbers: "inferred minimum values, and … not guaranteed to be
   exact". Cisco's sender counts loss from TX/RX packet counters per window, and its oper model
   has no sequence-number fields and no per-direction loss (D3).

## 4. Where zebra-rs stands

- **Counting.** `on_tx_tick` calls `window.record_sent()` when a probe is sent, and
  `on_reply_recv` calls `window.record_delay()` when a *valid* reply arrives
  ([inst.rs](../../zebra-rs/src/stamp/inst.rs)). Both counters reset at every export tick.
  `StatsWindow::loss_pct` reports `(sent − received) × 100 / sent` as an integer percent,
  display only.
- **Two latent faults in that count**, harmless while it is only displayed but wrong for an
  advertised value:
  - *Window-boundary skew.* A probe sent just before an export tick has its reply counted in
    the next window. Window N reads one loss too many and window N+1 one reply too many; the
    `saturating_sub` then hides the negative.
  - *Timestamp faults counted as loss.* A reply rejected for an implausible delay
    (`MAX_PLAUSIBLE_DELAY_US`, a bad reflector clock) is never counted as received, so a
    clock problem is reported as packet loss.
- **Reflector.** Stateless
  ([reflector.rs](../../zebra-rs/src/stamp/reflector.rs): "the reflector's own sequence
  number is a copy of the sender's"). A zebra-rs pair can therefore measure only round-trip
  probe loss.
- **Sender matching.** Replies are matched by SSID only. The reflected packet's
  `sender_seq` field ([packet.rs](../../crates/stamp-packet/src/packet.rs)) is parsed but not
  used.
- **Export.** One `MetricSnapshot` per export tick carries delay values and per-value
  Anomalous flags. The damping filter (`max(previous / 10, 50 µs)`) and per-subscriber flag
  comparison decide whether to notify
  ([damping.rs](../../zebra-rs/src/stamp/damping.rs),
  [anomaly.rs](../../zebra-rs/src/stamp/anomaly.rs)). A `None` snapshot means "no replies
  this window" and **withdraws every measured field**: IS-IS maps it to
  `LinkTeMetric::default()` in `process_stamp_event`
  ([isis/inst.rs](../../zebra-rs/src/isis/inst.rs)).
- **Carriers.** `LinkTeMetric.loss` already exists and already reaches sub-TLV 36
  ([isis/link.rs](../../zebra-rs/src/isis/link.rs) `sub_tlvs`, with `anomalous: false`
  hard-coded), OSPFv2 sub-TLV 30 and OSPFv3 16
  ([ospf/link.rs](../../zebra-rs/src/ospf/link.rs) `asla_sub_subs`: "loss is never measured
  today, so it can only be static"). The IS-IS BGP-LS translation already emits TLV 1117.
- **Static vs measured.** `merged_over`: a configured static leaf wins field by field, a
  measured value fills the rest, and a static field always originates its A bit clear. The
  static `loss` leaf takes raw RFC units (0–16777214).

## 5. Design

### D1 — Source: synthetic loss from the existing delay probes

Count loss on the probes the delay session already sends. That means no second session, no
new socket and no new wire format. It is what Cisco XR's delay-profile loss and Huawei's
TWAMP Light loss do.

Counter-based "direct mode" loss (Cisco IOS XE's SDLM, Cisco XR's counter sessions, the RFC
8972 Direct Measurement TLV) measures real traffic rather than probes, and so resolves far
smaller loss rates. It needs a peer that reports its receive counter, though, and the
counter source and its skew are a design of their own. It is deferred (§9), not rejected.

### D2 — Account by sequence number, and settle each probe after a waiting time

Replace the two window counters with per-probe accounting:

- On send, record `(seq, sent_at)` in a small outstanding queue. It is bounded: at the
  fastest probe interval (100 ms) and a 3 s waiting time, 30 entries.
- On a reply, match it by the **copied `sender_seq`** (not the SSID alone) and mark that probe
  *received*. **It counts as received whether or not its delay sample is plausible**: the
  packet came back, so it was not lost. A timestamp fault is a delay problem, and it keeps
  being counted in `rx_invalid` as today. Duplicate replies are ignored.
- A probe with no reply after **`LOSS_WAIT` = 3 s** (RFC 7680's *Tmax*) is settled *lost*.
  A reply arriving later is still lost for loss accounting, as RFC 7680 defines. The delay
  path is untouched, so this project changes no delay behaviour.
- **The deadline is judged against the reply's receive time**, taken at the socket read on
  the same monotonic clock as the send time. It is not judged when the event loop gets
  round to the reply, and it is not left to the next sweep. With a 10 s probe interval
  nothing sweeps for 10 s, and a reply 4 s late must not count as received. The reverse race
  is handled too: a reply read in time for a probe that a later sweep already declared lost
  moves that probe back to received. (PR 1 review, finding 1.)
- A probe is credited to the loss bucket (D4) **it was sent in**, received or lost — RFC 8570's
  "percentage of the total traffic sent over a configurable interval", literally. A bucket is
  **final** `LOSS_WAIT` after it ends, when every probe sent in it has settled, and only final
  buckets enter a window. This removes the boundary skew: every probe is counted exactly once,
  as received or as lost, in one bucket. (PR 1 booked each probe at its settlement time — the
  receive time or the deadline. PR 2 moved to send time, because deadline booking put an
  outage's last 3 s of probes into the first bucket after it as losses; see D8.)

`LOSS_WAIT` is a constant, not a knob. It has to exceed any real one-link round-trip time by
a wide margin and be much shorter than a 30 s loss bucket, and 3 s satisfies both at every
supported interval. RFC 8570 §5 requires measurement and advertisement intervals to be
configurable, not the loss waiting time.

### D3 — Direction: round-trip by default, forward-only against a stateful reflector

RFC 8570 advertises *unidirectional* loss. A stateless reflector makes forward and reverse
loss indistinguishable, because the sender only sees that a reply is missing.

- **Default: advertise round-trip probe loss as the unidirectional value.** It is an upper
  bound on forward loss (`p_rt ≈ p_fwd + p_rev` for small rates). Overstating loss steers
  traffic away from a link that is only lossy in the other direction; understating it would
  leave traffic on one that really is lossy. Halving it would assume symmetric loss, which
  nothing justifies. `show` labels the value **round-trip**. (Settled in review, §10
  decision 2.)
- **`peer-reflector stateful`** (per link, under `loss`): declares that the *peer's*
  reflector keeps its own sequence counter — a zebra-rs peer with `reflector stateful`, or a
  Juniper peer with `stateful-sequence`. The split then works as follows (review round 1,
  finding 1, replaced an earlier rule that subtracted consecutive replies in arrival order —
  reordering broke it, and it could count a probe twice):
  - **Direction classifies; it never counts.** Every probe is booked exactly once, at
    settlement (D2), as received or lost. A lost probe starts *unresolved*. Direction can only
    move a lost probe from unresolved to *forward* or *reverse*, so
    `forward + reverse + unresolved = lost` at all times. No probe can appear both as
    round-trip loss and inside a directional gap.
  - **Gaps are formed in sender-sequence order, not arrival order.** A gap is a maximal run of
    lost probes, consecutive in Session-Sender sequence number (serial arithmetic, RFC 1982
    style), bounded by a received probe `A` below and a received probe `B` above. It closes
    only when **every member has settled** — `LOSS_WAIT` has passed for the newest. A reply
    that is merely reordered therefore never forms a gap: `(10,10), (12,12), (11,11)`
    reports no loss in either direction, because probe 11 is still outstanding when 12's reply
    arrives, and received by the time it would settle.
  - **Classification:** with `g` members, `d = serial(R_B − R_A) − 1` probes reached the
    reflector in between, so `reverse = d` and `forward = g − d`. Only `0 ≤ d ≤ g` is
    accepted. Anything else — a reflector counter restart (the peer rebooted, its session was
    re-created, or `reflector stateful` was toggled), forward-path reordering across the gap,
    a counter that moved backwards — leaves the gap **unresolved**. That can never produce a
    negative or wrapped count; it falls back to round-trip. A run with no received probe
    below it, at the start of a session, has no anchor and stays unresolved too.
  - **Late replies** (after `LOSS_WAIT`) leave the probe lost, as RFC 7680 defines, and are
    not used as anchors. The reflector still counted that probe, so `d` includes it and the
    gap classifies it as reverse loss: it reached the peer, and its reply did not come back in
    time. `show` counts late replies separately. Duplicate replies are ignored.
  - **Long outages:** a reverse-path burst longer than `LOSS_WAIT` settles its probes as
    lost/unresolved while it lasts. The gap closes once the first reply after the burst has
    arrived and the gap's newest member has settled, and `d` then moves them to reverse. A
    forward-path burst closes with `d = 0`, all forward. Each open gap remembers which
    buckets its members settled in, so a late classification updates those buckets while
    they are still in a window (D4). Memory is O(1) per open gap: an anchor, a count and a
    short per-bucket tally, not one record per probe.
  - **What is advertised:** a `peer-reflector stateful` subscriber advertises
    `(forward + unresolved) / settled`. Unresolved counts as forward, the upper bound, in line
    with decision 2. So an open burst reads high until its gap closes, and never low.
  - **Limit:** forward-path reordering *within* a gap can shift attribution between the two
    directions by up to the reordering depth. It never changes the round-trip total. Juniper
    documents the same limit: its directional drops are "inferred minimum values … not
    guaranteed to be exact".
- **Implementation (PR 4).**
  - Gaps are formed as settled probes retire from the pending queue, which happens in send
    order and only once the head of the queue has settled. That is exactly "sender-sequence
    order, closed only when every member has settled". A reply that is merely reordered
    never forms a gap, and at a loss tick every gap of a bucket that just became final has
    already closed.
  - A gap spread over several buckets is split in proportion. Each bucket gets
    `floor(d·seen/g)` minus what earlier buckets took, so the shares add up to `d` exactly;
    only the gap-level split is actually known.
  - A break in the sender's sequence resets the open gap to unresolved. That is defensive:
    only successful sends are numbered.
  - One race remains: a reply read in time but processed after the sweep that settled its
    probe, while that probe's gap is already closed or still open. The reply proves the probe
    reached the reflector, which is what the reverse share counts. So `unlose` takes it from
    the bucket's reverse count first, and a classification is clamped to what its bucket has
    left. `forward + reverse ≤ lost` always holds, and the race costs at most one probe's
    attribution.
  - The reflector's counter runs for every probe received from the peer, whatever the mode;
    only its use in the reply depends on the mode. `build_reply` stays pure: the caller
    supplies the number.
  - **Changing a subscriber's `peer-reflector` starts its advertisement over** (PR 4
    review). Round-trip and forward loss are different quantities, and the old value is no
    baseline for the new one. Kept as one, a 0.833 % round-trip value on a link whose loss is
    all reverse stayed advertised as forward loss indefinitely, because the correction to
    0 % was under the 1.0-point minimum change. The subscriber's advertised value, cadence
    and A-bit state are reset, and an event goes out at once with whatever the new view gives.
    That event goes out even when the new view gives nothing, so the IGP withdraws the old
    value instead of keeping it.
  - **An open gap's history is bounded by the ring** (PR 4 review). A silent return path
    with the adjacency up keeps one gap open indefinitely. The gap keeps per-bucket member
    counts only for buckets still in the ring. Members in buckets that have rolled out are
    folded into one count, which still sets the gap's size and each kept bucket's
    proportional share.
- **The mode is configured, not detected.** A stateless reflector on a link with forward loss
  and a stateful reflector on a link with reverse loss produce *identical* reply streams: in
  both, the sequence numbers stay equal. No amount of observation tells them apart, and
  guessing wrong puts reverse loss into the forward advertisement.
- **zebra-rs's own reflector stays stateless by default; `reflector stateful` is opt-in**
  (per link, under `measurement`; settled in review, §10 decision 3). That is Juniper's model,
  and Cisco's reflector has no stateful mode at all. When set, the reflector keeps a counter in
  the per-session entry `reflect_allowed` already looks up — zebra-rs reflects only for peers
  it also measures, so the state is bounded by configured links, not a client cache. Two
  zebra-rs routers get directional loss by setting `reflector stateful` on one and
  `peer-reflector stateful` on the other.
- **What turning it on does to other senders**, as far as the vendors document it: a Juniper
  sender gains per-direction drops, which is what `stateful-sequence` exists for. A Cisco
  sender should be unaffected — its oper model has no sequence-number fields and counts loss
  from TX/RX counters — but how it matches replies to probes is not documented, so that rests
  on an interop test, not a citation. A zebra-rs sender matches by SSID and reads the copied
  Session-Sender timestamp, so it is unaffected.

### D4 — Loss is averaged over its own window, the loss interval

Loss runs on **its own 30 s bucket clock**, independent of the delay export period
(`damping-period`). 30 s is RFC 8570 §7's default measurement interval. Each session keeps a
ring of settled counts per bucket, and a subscriber's loss interval covers the last
`N = loss-interval / 30 s` buckets. The **default loss interval is 120 s**, so N = 4. The
advertised value is

```
loss = Σ lost / Σ settled   over the subscriber's last N buckets
```

**Buckets are indexed by time**, from the session's start: bucket *k* covers
`[start + k·30 s, start + (k+1)·30 s)`, and holds the probes sent in that span (D2). The
loss clock ticks `LOSS_WAIT` after each boundary, just as the previous bucket becomes final,
and only advances time. If ticks are skipped — a runtime stall, a VM freeze — the elapsed
boundaries become buckets with no probes, never one bucket stretched over several periods. So a window of N buckets always
spans exactly N × 30 s. A measurement gap then shows up as an integrity dip (D5), instead of
keeping old losses past their window. (PR 1 review, finding 2: the first cut closed one
bucket per tick, and a stall let a "120 s" window cover 240 s.)

This is literally RFC 8570's "percentage of the total traffic sent over a configurable
interval". It is the same shape as Cisco's periodic window and Nokia's 12 × 10 s aggregate.

A rolling *sum* rather than an exponentially weighted average: the sum states exactly what
it covers ("loss over the last 120 s"), forgets a burst on a known date, and makes the
resolution (D5) a plain count. An EWMA never quite forgets and has no sample count to show.

`loss interval` must be a multiple of 30 s (30–3600 s). The configuration layer rejects
anything else rather than silently rounding it: the commit fails and names the line. YANG
cannot express a step, and a protocol's config callback cannot reject a value once the commit
is dispatched, so the config manager checks the leaf before dispatch (`config::check`).
The two decimal64 percentages (`minimum-change`, `accelerated-threshold`) are checked the same
way, because libyang enforces neither a decimal64 range nor `fraction-digits`: 0–100 %, at
most six decimal places. PR 2 review, finding 1: a rejected value used to reach the running
config while STAMP kept its previous setting. The constraint sits on the **new** leaf only,
so it cannot invalidate an existing configuration. Review round 1, finding 2, caught that the
first version tied loss buckets to `damping-period`, which accepts any value from 1 to
3600 s: once loss became default-on, an existing `damping-period 7` or `300` would have
conflicted with the 120 s default and been rejected on upgrade.

Each bucket records the probes settled in it, the lost ones by class (D3), and the number of
probes the probe interval *then in force* should have produced. So a probe-interval retune
(D10) leaves the buckets valid, and the integrity check (D5) stays exact across it.

### D5 — Integrity gate, and resolution shown rather than hidden

- **No measured loss until the subscriber's window is full** (N buckets). A freshly started
  session advertises static loss if one is configured, and otherwise none. A loss value
  computed from ten probes is noise in a unit of 0.000003 %.
- **Window integrity:** the window must hold at least `integrity` % (default 90) of the
  probes its buckets expected — the sum of each bucket's own expected count (D4), not
  `loss-interval / interval` at today's rate. That catches send failures and a stalled
  session, and stays exact across an interval retune. The concept is Nokia's
  `window-integrity`.
- **Resolution is `100 % / Σ settled`**: 0.83 % at the defaults (1 probe/s over 120 s),
  0.083 % at 10 probes/s. That is the smallest loss rate this method can express, and `show`
  prints it next to the value. This is the honest limit of synthetic probing, and why D6's
  default minimum change is not smaller.
- **Encoding:** `round(loss × 100 / 0.000003)`, capped at 16777214 (50.331642 %) as RFC 8570
  requires.

### D6 — Loss has its own advertisement filter, and advertises on the RFC cadence

Delay's filter (`max(previous / 10, 50 µs)`) is in microseconds and cannot be reused, and
RFC 8570 §5 asks for per-sub-TLV filters anyway. Loss is evaluated at every loss bucket close
(30 s, D4), for each subscriber, but:

- **Periodic:** re-advertise **at most once per loss interval**, and only when
  `|new − advertised| ≥ max(threshold % × advertised, minimum-change)`. The interval is
  **real time elapsed** since the advertisement, not a count of buckets finalised since (PR 2
  review, finding 2). A subscriber seeded between ticks (a late-joining IGP, a config edit)
  is advertised at once, and the next tick may finalise a bucket a second later; counting
  buckets, that re-advertised at once. Every decision is timed by the real clock at the
  moment it is made, a tick's included. The first fix timed a tick on the 30 s grid, the
  instant its bucket became final. A second review found that backdated the cooldown when
  the event loop ran a tick late: a tick due at 123 s, run at 152 s, let the 153 s tick
  re-advertise one second later. Real ticks are not exactly 30 s apart either, so the
  comparison allows `CADENCE_SLACK` (1 s). Without it, a tick run a few milliseconds sooner
  after its predecessor would push roughly every other periodic update out by a whole tick.
  A re-advertisement can therefore come at most 1 s short of the interval, never sooner. The defaults are
  `threshold` **10 %** (zebra-rs delay and Juniper delay; Cisco XE uses 15 %) and
  `minimum-change` **1.0 percentage point** (settled in review, §10 decision 1).
- Why 1.0 and not Cisco XE's 0.2: Cisco XE counts real traffic, so its resolution is fine.
  At the default probe rate one probe is 0.83 %, so a minimum change below that suppresses
  nothing, and a link dropping one stray probe would flap between 0 and 0.83 % every
  interval. An operator who wants finer loss should raise the probe rate *and* lower the
  minimum change; D5's `show` output makes the relationship visible.
- **Accelerated** (RFC 8570 §5 SHOULD): an optional `accelerated-threshold`, **unset by
  default**. When set, a tick where the *latest bucket alone* differs from the advertised value
  by at least that many percentage points advertises immediately, using that bucket's value —
  Cisco's probe window. Its A bit is evaluated on that same value (D7). Off by default because
  the A bit already gives an immediate signal: a sudden 50 % loss lifts the 120 s average to
  12.5 % within one tick, past any sensible anomaly bound, and a flag change always
  advertises at once.
- The zero crossings follow the same rule: `0 → x` and `x → 0` are governed by
  `minimum-change`, since a relative threshold on zero is meaningless.

### D7 — Anomalous bit: reuse the delay hysteresis, bounds in percent

- `anomaly-threshold` / `reuse-threshold` under `loss`, in **percent** (decimal64, 6
  fraction digits). The pair follows Cisco XR's `anomaly-loss upper-bound` / `lower-bound`
  and Cisco XE's `anomaly-check` bounds.
- **The bounds are compared with the exact measurement**, not with the encoded value (PR 3
  review). The bounds are kept in micro-percent as configured. The candidate's loss is taken
  as `lost × 10⁸ / settled` micro-percent, rounded down, which is exact against a whole
  micro-percent bound. The encoded value fails in two ways. It saturates at 50.331642 %, so
  80 % measured loss never met a configured 60 % bound, and the sub-TLV then carries the cap
  *with* A. It is quantised to 0.000003 %, so a 0.000001 % bound truncated to zero and marked
  a clean link anomalous, with no way to recover.
- **The bit is evaluated on the value it is advertised with** (review round 1, finding 4).
  At each loss tick a subscriber has exactly one candidate: the rolling window (D4), or the
  latest bucket when the accelerated condition fires (D6). The existing `Anomaly` hysteresis
  runs on that candidate — at or above the anomaly bound sets, the band between the bounds
  holds. RFC 8570 §4.4 sets the bit "when the measured value of this parameter exceeds its
  configured maximum threshold", and the parameter is the value in the same sub-TLV. So after
  three clean buckets and one at 10 %, an accelerated advertisement carries 10 % *with* A set
  against a 5 % bound, although the rolling value is only 2.5 %. The first version evaluated
  the rolling value regardless, and would have sent 10 % with A clear.
- **A flag change advertises its candidate with it**, bypassing D6's cadence and value
  filter. Otherwise a suppressed value could travel with a flag computed from a different
  one: 4.8 % still advertised, A set because the rolling value just crossed 5 %. Every
  advertised `(value, A)` pair is therefore one the hysteresis produced from that value.
  Delay already behaves this way: a flag-only delay export sends the current window's values.
- **Set at once; clear only after a full loss interval below the reuse bound** (review round
  1, finding 6). Clearing needs every evaluation to have been below the reuse bound for a
  continuous elapsed time of at least the subscriber's loss interval (120 s by default). Any
  evaluation at or above the reuse bound restarts that timer. That, not the band, is what
  meets RFC 8570 §5's "below … for one or more advertisement intervals". The band
  establishes no elapsed time, and a rolling value can dip under the reuse bound one 30 s tick
  after the loss stops. The first version claimed the band sufficed. The existing `Anomaly`
  gains an optional minimum recovery time.
  Delay does not need one: its window resets at every export, so each delay evaluation
  already averages exactly one advertisement interval of that sub-TLV.
  Implemented in PR 3 as `Anomaly::evaluate_bounds(value, bounds, Some((now, min)))`. The wait
  is timed by the real clock and allows D6's `CADENCE_SLACK`, so tick jitter cannot hold the
  bit for an extra tick.
- **A withdrawal forgets the state.** When loss is disabled, the window is untrusted or a
  bucket goes silent (D8), the hysteresis resets, as delay's does after an empty window. A
  value that comes back has to cross the anomaly bound again, rather than inherit a bit from
  before the outage.
- **Per subscriber**, as for delay: IS-IS and OSPF configure their bounds separately and must
  not overwrite each other (`client::Subscriber`).
- **Unset means the bit is never set**, the same opt-in stance as delay. Cisco XE's 0.5 % /
  5 % defaults are documented as a starting point, not applied.
- `LinkTeMetric` gains `loss_anomalous`. `merged_over` clears it when a static `loss` is
  configured, exactly as it does for the delay flags.

### D8 — Total silence withdraws; partial loss is advertised

If a subscriber's window settled probes but **received none**, the measured loss is
**withdrawn**, not advertised as 50.33 %. Real 100 % loss on a P2P link also kills the IGP
adjacency, so a link whose adjacency is up while every probe vanishes has a measurement
problem: a reflector not running, an ACL, or a policer on the probe DSCP. Advertising the
maximum would make every Flex-Algo loss constraint in the domain prune a link that is
forwarding traffic. Liveness belongs to BFD and the IGP hello.

This matches delay, whose empty window already withdraws. Any received reply keeps the value
advertised, capped per D5.

**Silence is judged per bucket, and a silent bucket is a gap, not loss** (PR 2 BDD finding).
Judging silence only over the whole window was not enough. When the drop began, the bucket
that was open still held replies from before it, so the window was never "silent" while the
outage began. With the default 120 s window, a dead reflector read as rising loss up to the
50.33 % cap for as long as ~90 s. The same happened in reverse after recovery: the silent
buckets still in the window counted as lost probes. Two rules close it:

1. **The latest bucket is silent → withdraw at once**, whatever the integrity setting. The
   measurement has gone silent *now*.
2. **A silent bucket is a gap:** its probes count as neither settled nor lost, but they still
   count as expected. So a gap lowers the window's integrity (D5) instead of inflating its loss,
   and after recovery nothing is advertised until the window refills with real measurements —
   the same way a scheduler stall is treated (D4).

A bucket counts as silent only if **at least 10 probes settled** and none was received. At a
slow probe rate, a bucket holds only a few probes, and all of them being lost is ordinary loss:
3 probes at a 10 s interval are all lost 12.5 % of the time under 50 % loss. At the default 1 s
rate, silence is 30 consecutive losses. Below the floor, the whole-window rule above still
applies.

An earlier residual is resolved by send-time booking (D2). With lost probes booked at their
deadline, an outage's last 3 s of probes landed as losses in the first bucket after recovery —
about 2.4 % for one advertisement interval at the defaults, after every outage. Booked in the
bucket they were sent in, they stay inside the silent buckets, and the first recovery bucket
reads clean.

### D9 — Delay and loss export independently

Today one `Option<MetricSnapshot>` means "all measured values or none". Loss now has its own
clock (D4), its own gates (D5) and its own withdrawal rule (D8), so the event carries the two
separately. Each event is **the complete state one subscriber should advertise**:

```rust
StampEvent::MetricUpdate {
    key,
    delay: Option<DelayAdvert>,  // today's stamped MetricSnapshot, renamed
    loss: Option<LossAdvert>,    // value, A bit, direction, resolution
}
```

- `Some(x)` means "advertise `x`" and `None` means "advertise nothing" — withdraw — for
  **that field**. There is no third meaning.
- **A field whose update is suppressed repeats that subscriber's last advertised value.**
  Delay exports every 30 s when its values move; loss changes at most once per loss interval.
  So most events carry a new delay and the same loss. Sending the latest loss there would
  bypass its filter, and sending `None` would withdraw it; repeating the last advertised value
  does neither.
- An event is sent to a subscriber when either field differs from what that subscriber was
  last sent. Filters and flags are per subscriber (D10), so two IGPs on one session can
  receive different events on the same tick.
- The IGP overwrites both measured fields from each event. It keeps no merge logic of its
  own, and a repeated event is harmless.
- A subscriber that joins a running session is evaluated at once against the current
  buckets and the cached delay snapshot, so it starts from real state.

Review round 1, finding 3, chose this over a three-state `Unchanged / Withdraw / Value`
update. The first version had only `Some` and `None`, which left the case of loss being
suppressed while delay exports undefined. A complete snapshot keeps the IGP side
stateless, and the "suppressed" case cannot be misread.

A 30 s window with no *valid* delay sample withdraws delay and leaves loss alone. That case
is possible under D2, since a reply with a bad timestamp now counts as received. Without the
split, IS-IS's `None => LinkTeMetric::default()` would wipe a perfectly good loss value.

### D10 — Configuration

Under the existing per-interface `te-metric measurement` block (IS-IS, OSPFv2, OSPFv3):

```
te-metric {
  loss 3000;                        # existing static leaf, raw units — still wins (merged_over)
  measurement {
    enabled true;                   # existing
    interval 1000;                  # existing: probe interval, ms
    damping-period 30;              # existing: delay export window, s
    anomaly-threshold …;            # existing: delay
    reuse-threshold …;              # existing: delay
    reflector stateful;             # new: how THIS router reflects the peer's probes;
                                    #      default stateless (D3)
    loss {                          # new; loss is measured whenever measurement is on
      enabled true;                 # default true; false turns loss off on this link
      interval 120;                 # loss window, s; multiple of 30, 30–3600 (D4)
      threshold 10;                 # periodic relative change, %            (D6)
      minimum-change 1.0;           # periodic absolute change, %-points     (D6)
      accelerated-threshold 5.0;    # %-points on the latest bucket; unset = off (D6)
      anomaly-threshold 5.0;        # %; unset = A bit never set             (D7)
      reuse-threshold 0.5;          # %; unset = no hysteresis band          (D7)
      integrity 90;                 # % of expected probes                   (D5)
      peer-reflector stateless;     # the PEER's mode: stateless | stateful  (D3)
    }
  }
}
```

**Loss measurement is on by default** wherever `measurement` is enabled, as on Cisco IOS XR
(§10 decision 4); `loss enabled false` turns it off per link. That is a visible change on
upgrade, and the release notes must say so:

- Every measured link starts advertising sub-TLV 36 (and OSPF 30/16, BGP-LS 1117) once its
  first full loss window has settled — about 120 s after the session comes up (D5). A clean
  link advertises 0 %, which RFC 8570 gives no special meaning, unlike delay variation.
- Each such LSP grows by one sub-TLV per measured link, inline and again inside the ASLA.
- A router elsewhere running a Flex-Algo loss constraint starts seeing values it did not see
  before. On a clean link that is 0 %, below any constraint.
- The Anomalous bit stays off unless its bounds are configured (D7), so the default cannot
  raise an anomaly on its own.
- A static `loss` leaf still wins over the measured value (`merged_over`).

The existing leaf descriptions are reworded where they now mean something narrower:
`damping-period` becomes the delay export window only (loss has its own clock, D4), and
`measurement`'s help ("Measure this link's delay") gains loss.

**Who owns each setting.** IS-IS and OSPF measuring the same link share one session: one
probe stream, one set of loss buckets. Review round 1, finding 5, asked which of the new
settings belong to the shared session and which to each IGP, and what happens when they
disagree. The rule: a setting is shared only if it is **wire-visible**. Everything that
decides what an IGP *advertises* is per subscriber, evaluated over the shared buckets. That is
how the delay anomaly bounds already work, and for the same reason — a shared value would let
one IGP's configuration silently change the other's advertisement.

| Setting | Owner | When IS-IS and OSPF disagree |
|---|---|---|
| probe `interval`, `damping-period` (existing) | session | last writer wins, as today |
| `reflector stateful` | session — it changes the packets this router sends | on if **any** current subscriber sets it; recomputed when a subscriber joins, leaves or changes |
| `loss enabled`, `interval`, `threshold`, `minimum-change`, `accelerated-threshold`, `anomaly-threshold`, `reuse-threshold`, `integrity`, `peer-reflector` | subscriber | no conflict — each IGP gets its own evaluation, and its own event (D9) |

Consequences:

- **Loss accounting always runs** on every session: settlement, buckets, gap
  classification. It is cheap, and `show stamp` uses it. `loss enabled false` only means
  that subscriber is sent `loss: None`. IS-IS enabling loss while OSPF disables it on the same
  link just works, and neither overrides the other.
- **`reflector stateful` uses "any", not last-writer-wins.** A second IGP subscribing with the
  default must not silently turn off the stateful reflection the first one configured,
  breaking the peer's directional loss. Turning it on is backward compatible (§3 item 8), so
  "any" is the safe resolution. A change of mode breaks the reflector's counter continuity,
  which the peer's D3 sanity rule absorbs as unresolved gaps.
- **The ring is as long as the largest current subscriber's `interval`** (at most 120 buckets
  of 30 s). Two IGPs may use different loss intervals over the same buckets.
- **`peer-reflector` per subscriber** works because the session classifies gaps regardless;
  each subscriber advertises the view it declared — round-trip, or forward.
- **A shared probe-timing retune keeps the buckets.** Each bucket carries its own expected
  count (D4), so integrity and resolution stay exact across the change. Only a session
  re-creation (today, a `dst_port` change) clears the buckets, and every subscriber's gates
  (D5) then re-arm.

### D11 — Show output

`show stamp session` gains a loss block per session, for example:

```
  Loss (round-trip, 120s window): 1.667%  (2 of 120 probes)  resolution 0.833%
    integrity 100%  advertised 0.833% (next periodic in 74s)  A-bit clear
```

With `peer-reflector stateful`, the direction line splits into forward and reverse. The IGP
database displays already render sub-TLV 36; they gain the A-bit marker the delay sub-TLVs
show.

## 6. Carriers — no new code points

| Protocol | Sub-TLV | Builder today |
|---|---|---|
| IS-IS | 36 — inline in TLV 22 and MT TLV 222, and inside the ASLA (`isis/lsp.rs`) | `LinkTeMetric::sub_tlvs` — replace the hard-coded `anomalous: false` |
| OSPFv2 | 30 (ASLA in the Extended-Link LSA) | `asla_sub_subs` |
| OSPFv3 | 16 (ASLA in the E-Router-LSA) | `asla_sub_subs_v3` |
| BGP-LS | TLV 1117 | the IS-IS translation — unchanged; the value arrives already encoded |

Static loss keeps originating a clear A bit, as delay does today.

## 7. Testing

- **Unit, each mutation-verified:**
  - D2: settlement by sequence number. Includes a regression test for the boundary skew —
    a probe sent just before a tick, whose reply lands just after it, must count as received
    once and never as lost. Also: a reply with a bad timestamp counts as received, a
    duplicate reply is ignored, and a reply after the waiting time stays lost.
  - D3 — the invariant: after every operation, `forward + reverse + unresolved = lost`.
    Then, each with its expected split:
    - return-path reordering `(10,10), (12,12), (11,11)`: no loss in either direction, no
      wrapped value;
    - forward-path reordering with no loss: no loss;
    - a reverse-path burst longer than `LOSS_WAIT`: unresolved while it lasts, all reverse
      once the gap closes;
    - a forward-path burst longer than `LOSS_WAIT`: all forward;
    - a late reply: the probe stays lost and is classified reverse;
    - a reflector counter restart inside a gap: the gap stays unresolved and nothing goes
      negative;
    - sender and reflector sequence wrap at 2³²;
    - a stateless peer misdeclared `peer-reflector stateful`: every loss is classified
      reverse, which documents the configured-not-detected hazard;
    - the stateful reflector's per-session counter, and the "any subscriber" resolution.
  - D4: the loss clock is independent of `damping-period` (for example 7 s and 300 s both
    work with the 120 s default); ring rollover; a probe-interval retune keeps the buckets.
  - D5: the integrity gate against per-bucket expected counts, including across a retune; the
    window-full gate; the encoding cap.
  - D6: the filter truth table, including the zero crossings and the once-per-interval
    cadence.
  - D7:
    - three clean buckets then 10 % with acceleration on: advertises 10 % *with* A set against
      a 5 % bound;
    - a flag change carries its own candidate value, never a stale one;
    - A clears only after a full loss interval below the reuse bound, and a single evaluation
      back above reuse restarts the timer;
    - per-subscriber bounds.
  - D8: total silence withdraws; one received reply keeps the value advertised.
  - D9:
    - delay changes every export tick while loss is limited by its cadence: every event
      carries the same loss value, never `None` and never an unfiltered newer value;
    - a delay withdrawal leaves loss in place, and vice versa;
    - a late-joining subscriber starts from the current buckets.
  - D10: IS-IS with loss enabled and OSPF with it disabled on one session each get their own
    events; a second subscriber with the default does not turn `reflector stateful` off.
- **BDD — loss injected deterministically, not randomly.** `tc netem loss` is random, and a
  percentage assertion over 120 probes would be flaky. Drop exactly every *n*-th STAMP
  packet instead: nftables `numgen inc mod 10 == 0` on UDP 862, or iptables
  `-m statistic --mode nth --every 10`. That is exactly 10 % in the chosen direction.
  Scenarios:
  1. **On by default:** a measured link with no `loss` configuration advertises sub-TLV 36
     at 0 % once the window has filled, and `loss enabled false` withdraws it. This pins the
     default in both directions.
  2. **Loss on, 10 % forward drop:** IS-IS and OSPF advertise ≈ 10 % (the exact encoded
     value is deterministic).
  3. **Crossing the anomaly bound:** the A bit sets, then clears once the drop rule is
     removed and the value falls below the reuse bound.
  4. **Reverse-path-only drop:** with the default stateless reflector the sender advertises
     10 %; with `reflector stateful` on the far end and `peer-reflector stateful` on the near
     end it advertises ≈ 0 %. **This is the scenario that proves D3's direction handling.**
     A variant restarts the far-end session mid-run and checks the counter-restart rule.
     Another holds a reverse-path drop longer than `LOSS_WAIT`, and checks the advertised
     value falls back once the gap closes.
  5. **Probes dropped, adjacency up:** the loss sub-TLV is withdrawn, not maxed (D8).

  The existing features that enable measurement — `stamp_te_metric`, `stamp_v6_te_metric`,
  `stamp_v6_dad_retry` — will start carrying a loss sub-TLV. Their negative assertions look for
  the *delay* anomaly markers (`us (A)`, `(Anomalous)`), which a default-on loss with unset
  bounds does not produce, but PR 2 must run them and review each LSP expectation.
  `bgp_ls_te_metric` does not measure (its loss is static) and is unaffected.

## 8. Delivery — smallest PR first

1. **Accounting core:**
   - D2 per-probe settlement;
   - the independent 30 s loss clock and buckets, with per-bucket expected counts (D4);
   - the D5 computation;
   - `show` (D11).

   Nothing reaches an IGP, so it is safe to merge alone, and the boundary-skew fix lands first.
2. **Advertisement:**
   - the D9 complete per-subscriber snapshot;
   - D10 configuration and ownership rules;
   - the D6 filter and cadence;
   - D8 withdrawal;

   all wired into IS-IS, OSPFv2 and OSPFv3. BDD scenarios 1, 2 and 5. **This PR changes what
   every measured link advertises** (decision 4). The CHANGELOG is written at release cut in
   this repo, so the PR states the change for that entry to carry; the PR also reviews the
   existing STAMP features listed in §7.
3. **Anomalous bit:** D7 — the flag evaluated on its own candidate value, and the recovery
   timer. BDD scenario 3.
4. **Direction:**
   - D3 gap classification;
   - the opt-in stateful reflector (`reflector stateful`, resolved "any");
   - the sender's `peer-reflector` declaration.

   BDD scenario 4 and its variants.

Then the documentation: the book's TE-metric chapter, the supported-RFC appendix, and
closing out step 4 of the review sequencing.

## 9. Out of scope, and why

- **Flex-Algo loss constraint**
  ([draft-ietf-lsr-flex-algo-link-loss](https://datatracker.ietf.org/doc/html/draft-ietf-lsr-flex-algo-link-loss)).
  This is the consumer this work unblocks. It is a separate change to both Flex-Algo graph
  builders.
- **IGP metric penalty on a loss anomaly** (Cisco 25.1.1 `metric fallback anomaly loss`).
  This is a routing action outside RFC 8570, and the same follow-on the delay anomaly is
  already waiting for. The A bit should be trustworthy first.
- **Counter-based direct-mode loss** (RFC 8972 Direct Measurement TLV, Cisco SDLM). It gives
  better resolution, but it needs peer support and a counter design; it gets its own document.
- **LAN circuits.** Measurement is P2P-only today, as it is at Huawei and in every Cisco
  example. The pseudonode problem is already recorded in the review document.
- **One-way loss with synchronized clocks.** Loss needs no clock synchronization. D3's
  opt-in stateful reflector is the directional answer.

## 10. Decisions for the reviewer

The recommendation is listed first in each.

1. **`minimum-change` default 1.0 % vs Cisco XE's 0.2 %.** **Decided 2026-09-24: 1.0 %.**
   It suppresses single-probe flapping at the default probe rate but hides sub-1 % loss until
   the operator raises the rate. The default is only what applies when the knob is unset:
   `loss minimum-change` (D10) overrides it per link, and should be lowered together with the
   probe `interval` (e.g. 100 ms gives 0.083 % resolution, where Cisco XE's 0.2 fits). Rejected
   alternatives: raising the default probe rate on loss-enabled links (10× the probes), and a
   default derived from the probe rate (less predictable than a fixed number).
2. **Round-trip loss advertised as unidirectional under a stateless reflector.**
   **Decided 2026-09-24: yes.** It is conservative — an upper bound on forward loss — and
   labelled round-trip in `show`. Rejected alternatives: advertising nothing without a
   stateful peer, which would leave most interoperability cases without loss; and halving
   the round-trip value, which assumes symmetric loss.
3. **Should zebra-rs's reflector become stateful?** **Decided 2026-09-24: opt-in, same as
   Juniper** — stateless by default, `reflector stateful` per link (D3). The original proposal
   was stateful by default. The vendor check changed it: both vendors copy the sequence
   number by default (Cisco always, Juniper unless `stateful-sequence`), and although neither
   documents a sender that would break, Cisco's reply matching is undocumented. The cost of
   opt-in is configuring both ends for zebra-rs-to-zebra-rs directional loss.
4. **Should loss measurement be opt-in?** **Decided 2026-09-24: no — on by default, like
   Cisco IOS XR**, with `loss enabled false` as the per-link off switch (D10). The original
   recommendation was opt-in, citing Huawei's explicit enable and the upgrade change. The
   decision follows Cisco instead, whose delay profile has no loss switch. The upgrade
   consequences are listed in D10 and must reach the release notes. The loss A bit stays opt-in
   (D7), so default-on loss cannot raise an anomaly by itself.

## 11. Design review round 1 — resolutions (2026-09-24)

Six findings against the reviewed design, all accepted. Each is resolved in the section named;
the tests that pin them are in §7.

1. **[P1] Directional accounting mishandled reordering and could count a probe twice** → D3.
   Direction became a classification of already-settled losses
   (`forward + reverse + unresolved = lost`). Gaps are formed in sender-sequence order and
   close only once every member has settled. Classification needs `0 ≤ d ≤ g`, or the gap
   stays unresolved. Late replies stay lost and classify as reverse. Unresolved probes are
   advertised as forward.
2. **[P1] Default-on loss would have invalidated existing configurations** → D4. The first
   version made the loss interval a multiple of `damping-period`, which accepts 1–3600 s. Loss
   now runs on its own 30 s clock; the multiple-of rule applies only to the new
   `loss interval` leaf.
3. **[P2] The export event could not say "unchanged"** → D9. Each event is now the complete
   state one subscriber should advertise. A suppressed field repeats its last advertised
   value; `None` only ever means withdraw.
4. **[P2] An accelerated value could carry an A bit computed from a different value** → D7.
   The bit is evaluated on the candidate it is advertised with, and a flag change advertises
   that candidate.
5. **[P2] Shared-session ownership of the new settings was unspecified** → D10.
   - Only wire-visible settings are shared. Probe timing keeps last-writer-wins, and
     `reflector stateful` is on if any subscriber sets it.
   - Everything that decides an advertisement is per subscriber, over shared buckets.
   - Buckets survive a probe-timing retune.
6. **[P2] Hysteresis enforced no recovery duration** → D7. The bit now clears only after a
   full loss interval continuously below the reuse bound. The band alone was wrongly
   claimed to meet RFC 8570 §5. Delay is unaffected: each delay evaluation already spans
   exactly one of its advertisement intervals.

## Sources

- RFC 8570 — [IS-IS TE Metric Extensions](https://www.rfc-editor.org/rfc/rfc8570.html) (§4.4, §5–§7)
- RFC 7471 — OSPF TE Metric Extensions (§4.4)
- RFC 8762 — [STAMP](https://www.rfc-editor.org/rfc/rfc8762.html) (§4, stateless and stateful reflector)
- RFC 7680 — [A One-Way Loss Metric for IPPM](https://www.rfc-editor.org/rfc/rfc7680.html)
- Cisco IOS XR YANG, release 26.2.1: `Cisco-IOS-XR-um-performance-measurement-cfg.yang`
  (interface delay profile: `computation-interval`, `tx-interval`,
  `advertisement periodic/accelerated`, `anomaly-loss upper-bound 1..99 / lower-bound 0..98`;
  revision 2023-10-26 "Add packet anomaly loss config for delay profiles") and
  `Cisco-IOS-XR-perf-meas-oper-sub*.yang` (loss probe window, periodic window, rolling average,
  `loss-a-flag-set`) — [YangModels/yang, vendor/cisco/xr/2621](https://github.com/YangModels/yang/tree/main/vendor/cisco/xr/2621)
- Cisco — [IS-IS penalties for link loss anomalies (Cisco 8000, 25.1.1)](https://www.cisco.com/c/en/us/td/docs/iosxr/cisco8000/is-is/isis-config-guide-cisco8000/is-is-protection-and-resiliency-enhancements-w/is-is-penalty-for-link-loss-anomaly.html)
- Cisco — [Configure Performance Measurement, IOS XE 17](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/seg_routing/configuration/xe-17/segrt-xe-17-book/m-sr-performance-measurement.html) (loss-profile, SDLM, anomaly-check defaults)
- Cisco — IOS XR Segment Routing Configuration Guides, "Configure Performance Measurement" (computation interval default 30 s, range 1–3600; periodic advertisement default 120 s, range 30–3600), e.g. [NCS 5500, 7.9](https://www.cisco.com/c/en/us/td/docs/iosxr/ncs5500/segment-routing/79x/b-segment-routing-cg-ncs5500-79x/configure-performance-measurement.html) and [ASR 9000, 7.8](https://www.cisco.com/c/en/us/td/docs/routers/asr9000/software/asr9k-r7-8/segment-routing/configuration/guide/b-segment-routing-cg-asr9000-78x/configure-performance-measurement.html)
- Juniper — [`light` (TWAMP server) statement: `stateful-sequence`](https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/statement/light-server-twamp-edit-services-evo.html); [Understand TWAMP (STAMP stateful reflection)](https://www.juniper.net/documentation/us/en/software/junos/flow-monitoring/topics/concept/twamp-overview.html)
- Cisco — [Configure Performance Measurement, IOS XR 7.4 (NCS 5500)](https://www.cisco.com/c/en/us/td/docs/iosxr/ncs5500/segment-routing/74x/b-segment-routing-cg-ncs5500-74x/configure-performance-measurement.html) (TWAMP Light reflector copies the Sequence Number)
- Juniper — [Enable Link Delay Measurement and Advertising in IS-IS](https://www.juniper.net/documentation/us/en/software/junos/is-is/topics/topic-map/enable-link-delay-advertise-in-is-is.html)
- Juniper — [Pathfinder: IS-IS TWAMP Light link delay features](https://apps.juniper.net/feature-explorer/feature/5703?fn=IS-IS+:+TWAMP+Light+-+Unidirectional+Link+Delay+Measurement+-+Flex+Algo+Path+Selection)
- Nokia SR OS YANG, release 26.7: `nokia-conf.yang` `oam link-measurement measurement-template` — [nokia/7x50_YangModels, latest_sros_26.7](https://github.com/nokia/7x50_YangModels/tree/master/latest_sros_26.7)
- Arista — [EOS IS-IS user manual (TWAMP Light dynamic link delay)](https://www.arista.com/en/um-eos/eos-is-is)
- Huawei — [metric-link-loss advertisement enable](https://info.support.huawei.com/hedex/api/pages/EDOC1100277644/AEM10221/04/resources/command/yunshan/METRIC-LINK-LOSS-ADV(ISISTEOM).html); [Configuring IS-IS Extended Attribute Advertisement (NE5000E)](https://support.huawei.com/enterprise/en/doc/EDOC1100562993/12d3110a/configuring-is-is-extended-attribute-advertisement-ipv4)
