# STAMP A-bit implementation review

Reviewed commit `596416bfa75ba7a3d1f7f8e81c9751db89f70dca` on 2026-09-16. Implementation source was not changed.

## Latest review: `4c562c24`

Reviewed commit `4c562c2474595edba0891dee0d7af35e9b57bb0e`. Both R1 and R2 below are fixed. No new functional findings were identified in this review.

- `Session::last_snapshot` now advances on every export tick, independently of numeric damping. Late subscribers evaluate their own policy against that current observation; numeric damping retains its separate comparison baseline.
- Both IS-IS and OSPF reconcile paths resubscribe in place when only params change, preserving subscriber hysteresis and measured values. They still unsubscribe and clear measured values on removal or a session-key change.
- New regression tests exercise a numerically damped threshold crossing followed by a late subscriber and a timing edit while delay is in the hysteresis band. The updated BDD scenario exercises the IS-IS reconcile path and waits for propagation before checking the retained bit.

Validation:

- `cargo test -p zebra-rs stamp:: --bin zebra-rs`: 58 passed, including both new regression tests and IPv4/IPv6 loopback integration tests.
- `cargo test -p zebra-rs --bin zebra-rs te_metric_tests`: 16 passed across the IS-IS and OSPF metric builders and static override cases.
- `git diff --check HEAD~1 HEAD`: passed.

BDD scenarios were inspected but not run during this review. The OSPF reconcile change was verified by source inspection; the new BDD timing-edit scenario exercises IS-IS only. This review does not establish complete RFC conformance. Implementation source was not changed.

Minor documentation follow-up: [the show-command book](../../book/src/ch-14-05-show-bfd-stamp-nd.md) still describes the summary as the last exported metric and names the JSON field `last_export`. The implementation now displays the last sample and emits `last_snapshot`; update that documentation to match. This is not a functional A-bit finding.

## Resolution

All five findings are fixed on branch `stamp-te-anomalous-bit`; the review
sections below are kept as written, as the record of what was found.

| # | Finding | Fixed in | Gate |
|---|---|---|---|
| 1 | Min/max A-bit evaluated from the window average | `666b417d` | `max_crosses_while_average_stays_inside`, `average_recovers_before_max` |
| 2 | One IGP could overwrite or disable the other's policy | `666b417d` | `anomaly_policy_is_per_subscriber` (both orders), `unsubscribing_does_not_leak_policy`, BDD: threshold under IS-IS alone |
| 3 | A static bound suppressed the other measured bound | `666b417d` | `pinned_bound_leaves_the_other_free_to_flag` |
| R1 | Flag-only exports left the late-subscriber cache stale | `4c562c24` | `late_subscriber_is_seeded_from_the_current_measurement` |
| R2 | IGP timing edits discarded hysteresis | `4c562c24` | `resubscribe_preserves_hysteresis`, BDD: widened band + interval edit |

Notes on the fixes, where they differ from the suggestion in the finding:

- **1 and 3 share one mechanism.** Rather than splitting hysteresis into
  "average" and "min/max" states, each of the three advertised values gets
  its own state and flag. The Min/Max sub-TLV's single bit is then the OR of
  its two bounds' flags, which makes finding 3 fall out for free: the merge
  clears only the pinned bound's flag, leaving the other free to raise the
  bit.
- **2** kept probe timing shared (last-writer-wins, as before) and moved only
  the policy — thresholds plus hysteresis — onto a per-client `Subscriber`
  record. The thresholds still ride in `SessionParams` so the IGP-side
  reconcile diff notices a threshold-only edit; a comment marks that the
  session itself ignores them.
- **R1** was resolved by changing what the cache means rather than adding a
  second one: `last_export` became `last_snapshot`, written every tick, with
  the value filter keeping its own baseline in `Damping` where it already
  did. `show stamp` renders it as "Last sample".
- **R2** also gated the measured-value clear on a real teardown, which the
  finding did not mention: a params-only edit had additionally been
  withdrawing and re-advertising the sub-TLVs.

Every fix was mutation-tested — each gate was confirmed to fail with its fix
reverted. That caught a false gate: the first BDD scenario for R2 passed with
the fix reverted, because `should eventually contain` is satisfied by the LSP
the previous scenario left in the database. It can show that a state appears,
never that it persists. An explicit settle wait past the damping period made
it discriminate.

## Re-review of `666b417d`

Reviewed follow-up commit `666b417d3262ca1dc9385ce81a87740856be1ba0`. All three original findings below are fixed: values have independent flags/hysteresis, subscribers own their anomaly policy, and static overrides suppress only the overridden bound's flag.

Two remaining P2 issues were found by tracing export and subscription lifecycle code:

### R1 — Flag-only exports leave the late-subscriber cache stale

Location: [stamp/inst.rs](../../zebra-rs/src/stamp/inst.rs), `on_export_tick` around lines 624–628, and `subscribe` around lines 365–372.

`session.last_export` is updated only when the numeric damping gate fires, although a subscriber flag transition can export a newer snapshot independently. `subscribe` subsequently evaluates anomaly against this older cached snapshot.

For example, configure a 1,000-us upper bound with reuse defaulting to the same bound. An initial 990-us snapshot is cached with clear flags. A later 1,010-us window is numerically damped (20 us movement is below the 99-us threshold), but sets the A-bits and is delivered to the current subscriber. The cache remains 990 us. A late subscriber with the identical policy immediately receives 990 us and clear flags, despite the current subscriber having received 1,010 us and set flags. The discrepancy lasts until another export tick and the text `Last export` also reports the older values.

Keep the latest raw observation available separately from the numeric damping baseline, and use the current observation for subscriber initialization. If `last_export` is intended to describe actual delivered exports, update its semantics for flag-triggered exports too. Add a regression with a numerically damped threshold crossing followed by a late subscriber.

### R2 — IGP timing edits discard subscriber hysteresis

Location: [isis/inst.rs](../../zebra-rs/src/isis/inst.rs), `stamp_reconcile_link` around lines 2513–2521; the corresponding unsubscribe/subscribe sequence in [ospf/inst.rs](../../zebra-rs/src/ospf/inst.rs); [stamp/inst.rs](../../zebra-rs/src/stamp/inst.rs), `unsubscribe` and `subscribe`.

The new `subscribe` implementation preserves hysteresis when an existing client resubscribes. The real IGP reconcile paths first unsubscribe whenever the desired params change, however, deleting that client record. The subsequent subscribe constructs a fresh `DelayAnomaly`.

With IS-IS and OSPF sharing a session, give IS-IS upper/reuse thresholds of 1,000/900 us. Export 1,100 us to set the bit, then 950 us to retain it in the hysteresis band. Change only IS-IS's probe interval or damping period. OSPF keeps the shared session alive, but IS-IS's unsubscribe deletes its hysteresis. Resubscription evaluates the cached 950-us snapshot from a clear initial state and immediately clears IS-IS's bit without delay falling below 900 us. With a single subscriber, the timing edit also tears down the session and later resumes with fresh hysteresis.

When the session key is unchanged, resubscribe in place to update params/notifier/policy; unsubscribe only for actual session removal or key changes. Add a regression exercising the IGP lifecycle, or the exact unsubscribe/resubscribe sequence it currently produces, while delay is in the hysteresis band.

### Re-review validation

- `cargo test -p zebra-rs stamp:: --bin zebra-rs`: 56 passed.
- `cargo test -p zebra-rs --bin zebra-rs anomal`: 18 passed.
- `cargo test -p zebra-rs --bin zebra-rs pinned`: 4 passed, including both protocols' partial static-bound tests.

The new tests cover the original findings, but not R1 or R2. The anomaly-transition test modifies subscriber thresholds directly, bypassing the real IGP unsubscribe/resubscribe lifecycle. BDD scenarios were not run. The two new findings are source-traced reproduction sequences, not executed regression tests. Implementation source remains unchanged.

## Findings

### 1. P1 — Min/max anomaly is evaluated from average delay

Location: [stamp/inst.rs](../../zebra-rs/src/stamp/inst.rs), `on_export_tick`, line 600; propagated to both delay sub-TLVs by [isis/inst.rs](../../zebra-rs/src/isis/inst.rs) and [ospf/inst.rs](../../zebra-rs/src/ospf/inst.rs).

The sole evaluator receives `snap.avg`, and its result becomes both the average-delay and min/max-delay A-bits. With an upper threshold of 1,000 us and samples of 100 and 1,500 us, the average is 800 us, so the advertised max is 1,500 us but the min/max A-bit stays clear. An existing min/max anomaly can also clear while max remains above the upper bound if average falls below reuse.

[RFC8570 section 4.2](https://www.rfc-editor.org/rfc/rfc8570.html#section-4.2) and [RFC7471 section 4.2.3](https://www.rfc-editor.org/rfc/rfc7471.html#section-4.2.3) define setting the min/max A-bit when one or more measured values exceed the configured maximum threshold. Avoiding a scheduling outlier is not a reason to use the average for this sub-TLV while advertising the outlier as max.

Use independent hysteresis states and snapshot flags for average and min/max. Evaluate min/max against its bounds; with a common threshold, max determines whether either bound crosses it. Add a test with average below threshold and max above it, and a recovery test where average recovers before max.

### 2. P1 — One IGP can overwrite or disable the other IGP's anomaly policy

Location: [stamp/session.rs](../../zebra-rs/src/stamp/session.rs), `MeasurementConfig::resolve`, lines 101–104, together with [stamp/inst.rs](../../zebra-rs/src/stamp/inst.rs), `update_params`, line 487.

Anomaly thresholds are configured independently under IS-IS and OSPF, but are now part of the single session-wide `SessionParams`. Existing subscription handling replaces those params with the latest subscriber's values. If IS-IS subscribes with a 1,000-us threshold and OSPF subsequently subscribes with its default unconfigured threshold, OSPF disables anomaly evaluation for the shared session and IS-IS advertises a clear bit despite its configured threshold. If IS-IS subscribes last, OSPF instead advertises IS-IS's anomaly despite having detection unconfigured. Different configured thresholds likewise become order-dependent. Removing the winning subscriber does not restore the remaining subscriber's policy.

Sharing probes is appropriate; sharing independently configured policy through last-writer-wins is not. Keep raw delay measurements shared and evaluate anomaly per subscriber/IGP, or explicitly require and validate a common policy. Add tests for one configured and one unconfigured subscriber in both subscription orders, distinct thresholds, and removal of a subscriber.

The added BDD scenarios configure the same threshold on both IGPs, so they do not cover this conflict.

### 3. P2 — A static min or max suppresses anomalies in the remaining measured bound

Location: [isis/link.rs](../../zebra-rs/src/isis/link.rs), `merged_over`, lines 632–634; [ospf/link.rs](../../zebra-rs/src/ospf/link.rs), lines 233–235.

The merge clears the entire min/max A-bit whenever either bound is static. For example, pinning min to 100 us while leaving max measured allows max to exceed the configured threshold without the min/max sub-TLV reporting that anomaly. One static bound does not make the other bound cease being a measurement. Both RFCs describe the bit as covering one or more measured values.

Evaluate whichever bounds remain measured, and suppress detection only for the overridden bounds. The new `one_pinned_bound_clears_the_min_max_bit` tests encode the current suppression behavior and should instead exercise a threshold violation in the remaining measured bound.

## Validation and positive observations

`cargo test -p zebra-rs stamp:: --bin zebra-rs` passed: 51 tests, no failures. The tests cover the scalar hysteresis state machine, flag transitions through damping, session sharing/retuning, and loopback exports. They do not cover the three cases above. The BDD scenarios were inspected but not run during this review.

`cargo test -p zebra-rs --bin zebra-rs anomal` also passed: 12 tests, including the IS-IS and OSPF flag builders and static average override cases.

The change correctly makes flag transitions bypass numeric change suppression, resets hysteresis on empty windows, carries flags through both protocol builders, and keeps fully static average-delay values from inheriting a measured anomaly. Anomaly-driven routing cost fallback remains outside this change's stated scope.
