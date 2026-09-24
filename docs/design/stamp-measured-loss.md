# Measured link loss for STAMP-driven TE metrics — design

> **Status:** proposal, awaiting review (2026-09-24)
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

1. **Loss is opt-in.** Huawei needs an explicit `advertisement enable`, and Cisco configures
   it per profile. Juniper, Nokia and Arista don't advertise measured loss at all, so a
   router that starts flooding sub-TLV 36 is doing something most of the network isn't.
   zebra-rs keeps it behind its own switch (D10).
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
- A probe is credited to the export window **in which it settles**, not the one in which it
  was sent. This removes the boundary skew: every probe is counted exactly once, as
  received or as lost.

`LOSS_WAIT` is a constant, not a knob. It has to exceed any real one-link round-trip time by
a wide margin and be much shorter than an export window, and 3 s satisfies both at every
supported interval. RFC 8570 §5 requires measurement and advertisement intervals to be
configurable, not the loss waiting time.

### D3 — Direction: round-trip by default, forward-only against a stateful reflector

RFC 8570 advertises *unidirectional* loss. A stateless reflector makes forward and reverse
loss indistinguishable, because the sender only sees that a reply is missing.

- **Default: advertise round-trip probe loss as the unidirectional value.** It is an upper
  bound on forward loss (`p_rt ≈ p_fwd + p_rev` for small rates). Overstating loss steers
  traffic away from a link that is only lossy in the other direction; understating it would
  leave traffic on one that really is lossy. Halving it would assume symmetric loss, which
  nothing justifies. `show` labels the value **round-trip**.
- **`reflector stateful`** (per link): the peer's reflector keeps its own sequence counter.
  Between two consecutive received replies `(S₁, R₁)` and `(S₂, R₂)`:
  - forward loss = `(S₂ − S₁) − (R₂ − R₁)`
  - reverse loss = `(R₂ − R₁) − 1`

  Both use wrapping arithmetic. Probes after the last received reply are unresolved; they
  settle as round-trip loss if the waiting time expires before another reply arrives.
- **The mode is configured, not detected.** A stateless reflector on a link with forward loss
  and a stateful reflector on a link with reverse loss produce *identical* reply streams: in
  both, the sequence numbers stay equal. No amount of observation tells them apart, and
  guessing wrong puts reverse loss into the forward advertisement.
- **zebra-rs's own reflector becomes stateful**, keeping a per-session counter in the entry
  `reflect_allowed` already looks up. A zebra-rs pair then gets directional loss both ways.
  This is backward compatible: every sender, including today's zebra-rs, identifies probes by
  the copied Session-Sender fields, which do not change. What changes is the reflector's
  *own* Sequence Number field, which a stateless-mode sender ignores.

### D4 — Loss is averaged over its own window, the loss interval

Keep a ring of the last *K* export windows' settled counts, where
`K = loss-interval / damping-period`. The **default loss interval is 120 s**, so K = 4 at the
default 30 s export period. The advertised value is

```
loss = Σ lost / Σ settled   over the ring
```

This is literally RFC 8570's "percentage of the total traffic sent over a configurable
interval". It is the same shape as Cisco's periodic window and Nokia's 12 × 10 s aggregate.

A rolling *sum* rather than an exponentially weighted average: the sum states exactly what
it covers ("loss over the last 120 s"), forgets a burst on a known date, and makes the
resolution (D5) a plain count. An EWMA never quite forgets and has no sample count to show.

`loss-interval` must be a multiple of the damping period. The configuration layer rejects
anything else rather than silently rounding it.

### D5 — Integrity gate, and resolution shown rather than hidden

- **No measured loss until the ring is full.** A freshly started session advertises static
  loss if one is configured, and otherwise none. A loss value computed from ten probes is
  noise in a unit of 0.000003 %.
- **Window integrity:** the ring must hold at least `integrity` % (default 90) of the
  probes the configured rate should have produced (`loss-interval / interval`). That catches
  send failures, a stalled session and interval retunes. The concept is Nokia's
  `window-integrity`.
- **Resolution is `100 % / Σ settled`**: 0.83 % at the defaults (1 probe/s over 120 s),
  0.083 % at 10 probes/s. That is the smallest loss rate this method can express, and `show`
  prints it next to the value. This is the honest limit of synthetic probing, and why D6's
  default minimum change is not smaller.
- **Encoding:** `round(loss × 100 / 0.000003)`, capped at 16777214 (50.331642 %) as RFC 8570
  requires.

### D6 — Loss has its own advertisement filter, and advertises on the RFC cadence

Delay's filter (`max(previous / 10, 50 µs)`) is in microseconds and cannot be reused, and
RFC 8570 §5 asks for per-sub-TLV filters anyway. Loss is evaluated at every export tick, but:

- **Periodic:** re-advertise **at most once per loss interval**, and only when
  `|new − advertised| ≥ max(threshold % × advertised, minimum-change)`. The defaults are
  `threshold` **10 %** (zebra-rs delay and Juniper delay; Cisco XE uses 15 %) and
  `minimum-change` **1.0 percentage point**.
- Why 1.0 and not Cisco XE's 0.2: Cisco XE counts real traffic, so its resolution is fine.
  At the default probe rate one probe is 0.83 %, so a minimum change below that suppresses
  nothing, and a link dropping one stray probe would flap between 0 and 0.83 % every
  interval. An operator who wants finer loss should raise the probe rate *and* lower the
  minimum change; D5's `show` output makes the relationship visible.
- **Accelerated** (RFC 8570 §5 SHOULD): an optional `accelerated-threshold`, **unset by
  default**. When set, a tick where the *latest export window alone* differs from the
  advertised value by at least that many percentage points advertises immediately, using
  that window's value — Cisco's probe window. Off by default because the A bit (D7) already
  gives an immediate signal: a sudden 50 % loss lifts the 120 s average to 12.5 % within one
  tick, past any sensible anomaly bound, and a flag change always exports at once.
- The zero crossings follow the same rule: `0 → x` and `x → 0` are governed by
  `minimum-change`, since a relative threshold on zero is meaningless.

### D7 — Anomalous bit: reuse the delay hysteresis, bounds in percent

- `anomaly-threshold` / `reuse-threshold` under `loss`, in **percent** (decimal64, 6
  fraction digits, matching the 0.000003 % unit). The pair follows Cisco XR's
  `anomaly-loss upper-bound` / `lower-bound` and Cisco XE's `anomaly-check` bounds.
- Evaluated on the **rolling value** (D4), the averaged quantity RFC 8570 advertises, by the
  existing `Anomaly` hysteresis: at or above the anomaly bound sets, below the reuse bound
  clears, the band in between holds. RFC 8570 §5's "below … for one or more advertisement
  intervals" is met by the band.
- **Per subscriber**, as for delay: IS-IS and OSPF configure their bounds separately and must
  not overwrite each other (`client::Subscriber`).
- **Unset means the bit is never set**, the same opt-in stance as delay. Cisco XE's 0.5 % /
  5 % defaults are documented as a starting point, not applied.
- A flag change exports on its own, bypassing D6's cadence. That is the existing
  `on_export_tick` rule.
- `LinkTeMetric` gains `loss_anomalous`. `merged_over` clears it when a static `loss` is
  configured, exactly as it does for the delay flags.

### D8 — Total silence withdraws; partial loss is advertised

If the ring settled probes but **received none**, the measured loss is **withdrawn**, not
advertised as 50.33 %. Real 100 % loss on a P2P link also kills the IGP adjacency, so a
link whose adjacency is up while every probe vanishes has a measurement problem: a
reflector not running, an ACL, or a policer on the probe DSCP. Advertising the maximum would
make every Flex-Algo loss constraint in the domain prune a link that is forwarding traffic.
Liveness belongs to BFD and the IGP hello.

This matches delay, whose empty window already withdraws. Any received reply keeps the value
advertised, capped per D5.

### D9 — Delay and loss export independently

Today one `Option<MetricSnapshot>` means "all measured values or none". Loss now has a
different window (120 s vs 30 s), a different gate (D5) and a different withdrawal rule
(D8). So the export event carries them separately:

```rust
StampEvent::MetricUpdate {
    key,
    delay: Option<DelaySnapshot>,  // today's MetricSnapshot, renamed
    loss: Option<LossSnapshot>,    // value, A bit, direction, resolution
}
```

Each IGP maps the two independently into `measured_te_metric`. A 30 s window with no *valid*
delay sample — possible under D2, since a reply with a bad timestamp now counts as received
— withdraws delay and leaves loss alone. Without this split, IS-IS's
`None => LinkTeMetric::default()` would wipe a perfectly good loss value.

### D10 — Configuration

Under the existing per-interface `te-metric measurement` block (IS-IS, OSPFv2, OSPFv3):

```
te-metric {
  loss 3000;                        # existing static leaf, raw units — still wins (merged_over)
  measurement {
    enabled true;                   # existing
    interval 1000;                  # existing: probe interval, ms
    damping-period 30;              # existing: export window, s
    anomaly-threshold …;            # existing: delay
    reuse-threshold …;              # existing: delay
    loss {                          # new; presence = loss measurement on
      interval 120;                 # loss window, s; multiple of damping-period (D4)
      threshold 10;                 # periodic relative change, %            (D6)
      minimum-change 1.0;           # periodic absolute change, %-points     (D6)
      accelerated-threshold 5.0;    # %-points on the latest window; unset = off (D6)
      anomaly-threshold 5.0;        # %; unset = A bit never set             (D7)
      reuse-threshold 0.5;          # %; unset = no hysteresis band          (D7)
      integrity 90;                 # % of expected probes                   (D5)
      reflector stateless;          # stateless | stateful                   (D3)
    }
  }
}
```

**Loss measurement is opt-in** (a `loss` presence container). Links measured today keep
advertising exactly what they do now after an upgrade. Turning it on by default would add
sub-TLV 36 to every measured link's LSP, and any router running a Flex-Algo loss constraint
would start pruning on it. That is the operator's decision, and Huawei and Cisco make it
explicit too.

The existing leaf descriptions are reworded where they now mean something narrower:
`damping-period` becomes the delay export window, and `measurement`'s help ("Measure this
link's delay") gains loss.

### D11 — Show output

`show stamp session` gains a loss block per session, for example:

```
  Loss (round-trip, 120s window): 1.667%  (2 of 120 probes)  resolution 0.833%
    integrity 100%  advertised 0.833% (next periodic in 74s)  A-bit clear
```

With `reflector stateful`, the direction line splits into forward and reverse. The IGP
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
  - D3: the stateful forward/reverse arithmetic, including sequence wrap-around.
  - D4: ring rollover.
  - D5: the integrity gate, the ring-full gate, and the encoding cap.
  - D6: the filter truth table, including the zero crossings and the once-per-interval
    cadence.
  - D7: hysteresis on the rolling value, and per-subscriber bounds.
  - D8: total silence withdraws; one received reply keeps the value advertised.
  - D9: a delay withdrawal leaves loss in place, and vice versa.
- **BDD — loss injected deterministically, not randomly.** `tc netem loss` is random, and a
  percentage assertion over 120 probes would be flaky. Drop exactly every *n*-th STAMP
  packet instead: nftables `numgen inc mod 10 == 0` on UDP 862, or iptables
  `-m statistic --mode nth --every 10`. That is exactly 10 % in the chosen direction.
  Scenarios:
  1. **Loss off:** no sub-TLV 36 appears on a measured link. This is the upgrade guarantee.
  2. **Loss on, 10 % forward drop:** IS-IS and OSPF advertise ≈ 10 % (the exact encoded
     value is deterministic).
  3. **Crossing the anomaly bound:** the A bit sets, then clears once the drop rule is
     removed and the value falls below the reuse bound.
  4. **Reverse-path-only drop:** `reflector stateless` advertises 10 %, `reflector stateful`
     advertises ≈ 0 %. **This is the scenario that proves D3's direction handling.**
  5. **Probes dropped, adjacency up:** the loss sub-TLV is withdrawn, not maxed (D8).

## 8. Delivery — smallest PR first

1. **Accounting core:** D2 plus D4/D5 computation, plus `show` (D11). Nothing reaches an IGP,
   so it is safe to merge alone, and the boundary-skew fix lands first.
2. **Advertisement:** the D9 event split, D10 configuration, D6 filter and D8 withdrawal,
   wired into IS-IS, OSPFv2 and OSPFv3. BDD scenarios 1, 2 and 5.
3. **Anomalous bit:** D7. BDD scenario 3.
4. **Direction:** D3 — the stateful reflector and the `reflector` knob. BDD scenario 4.

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
  stateful reflector is the directional answer.

## 10. Decisions for the reviewer

The recommendation is listed first in each.

1. **`minimum-change` default 1.0 % vs Cisco XE's 0.2 %.** 1.0 % suppresses single-probe
   flapping at the default probe rate but hides sub-1 % loss until the operator raises the
   rate. The alternative is to raise the default probe rate on loss-enabled links, which
   costs 10× the probes.
2. **Round-trip loss advertised as unidirectional under a stateless reflector.** It is
   conservative, and labelled in `show`. The alternative is to advertise nothing without a
   stateful peer, which would leave most interoperability cases without loss.
3. **zebra-rs's reflector becomes stateful** (D3). It is backward compatible per RFC 8762,
   but it is a behaviour change visible on the wire in the reflector's own Sequence Number
   field.
4. **Loss is opt-in** (D10), rather than on wherever measurement is enabled.

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
- Juniper — [Enable Link Delay Measurement and Advertising in IS-IS](https://www.juniper.net/documentation/us/en/software/junos/is-is/topics/topic-map/enable-link-delay-advertise-in-is-is.html)
- Juniper — [Pathfinder: IS-IS TWAMP Light link delay features](https://apps.juniper.net/feature-explorer/feature/5703?fn=IS-IS+:+TWAMP+Light+-+Unidirectional+Link+Delay+Measurement+-+Flex+Algo+Path+Selection)
- Nokia SR OS YANG, release 26.7: `nokia-conf.yang` `oam link-measurement measurement-template` — [nokia/7x50_YangModels, latest_sros_26.7](https://github.com/nokia/7x50_YangModels/tree/master/latest_sros_26.7)
- Arista — [EOS IS-IS user manual (TWAMP Light dynamic link delay)](https://www.arista.com/en/um-eos/eos-is-is)
- Huawei — [metric-link-loss advertisement enable](https://info.support.huawei.com/hedex/api/pages/EDOC1100277644/AEM10221/04/resources/command/yunshan/METRIC-LINK-LOSS-ADV(ISISTEOM).html); [Configuring IS-IS Extended Attribute Advertisement (NE5000E)](https://support.huawei.com/enterprise/en/doc/EDOC1100562993/12d3110a/configuring-is-is-extended-attribute-advertisement-ipv4)
