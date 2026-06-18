# TI-LFA Parallel SPF — Remaining Potential Tasks

Status: series COMPLETE for IS-IS and OSPF (2026-06-12).
Shipped: IS-IS #1384 (refactor + identity oracles), #1390 (modes +
config + telemetry), #1395 (BDD + perf harness); OSPF #1399 (v2+v3
port), #1400 (BDD). Design: `isis-tilfa-parallel-spf.md`.

This note collects the work that was identified during the series but
deliberately left out of scope, with code anchors and enough rationale
that any item can be picked up cold.

## 1. Flex-Algo TI-LFA (no producer at all today)

Both protocols compute per-algo SPFs but skip TI-LFA for them entirely
(`compute_spf` in `zebra-rs/src/isis/rib.rs` — "No TI-LFA for
Flex-Algo"; same in `ospf/inst.rs`). A per-algo repair must be
computed *within the algo's own constrained topology* (the algo-0
repair may traverse links the FAD excludes), and the repair segments
must resolve against per-algo Prefix-SIDs. The machinery is ready —
`spf::tilfa_compute` is graph-agnostic, so each algo's
`(graph, source, spf_result)` triple can feed it directly; the work is
target derivation per algo, per-algo SID resolution at install time,
and YANG (the per-algo `fast-reroute ti-lfa` containers already exist
as placeholders in `config.yang`).

## 2. Top-level SPF parallelism (phase A widening)

`compute_spf` still runs the independent top-level Dijkstras
sequentially: legacy → (TI-LFA) → MT2 → per-flex-algo (IS-IS), and
area-graph → (TI-LFA) → per-flex-algo (OSPF). The legacy SPF must
finish first (targets derive from it), but MT2 and every flex-algo SPF
are independent of it and of each other — they could join the rayon
fan-out alongside the TI-LFA phase-A jobs. Payoff is small unless many
flex-algos are configured (it saves ≤ `1 + |algos|` serial SPF times
per cycle), which is why it was deferred.

## 3. Q-space sharing for SRLG / multi-failure exclusion sets

`q_space_vertices` (`spf/calc.rs`) runs the reverse SPF *without* the
exclusion set — `x` only drives the path filter. Today each
destination has exactly one `(d, x)` pair so there is nothing to
share, but a future SRLG-aware TI-LFA (several `x` per destination,
one repair per shared-risk group) can reuse one reverse tree per `d`
across all its exclusion sets — the same identity-shaped saving that
I1/I2 exploited for P-space and the PC paths. Worth remembering before
anyone makes Q-space recompute per `(d, x)`.

## 4. Incremental TI-LFA

Every SPF cycle recomputes every target. Most LSDB changes leave the
majority of primary first-hops unchanged; a delta pass could recompute
only the targets whose `(d, x)` pair changed since the previous run
(the previous `tilfa_result` and per-x trees are at hand). This is the
largest remaining CPU win for incremental topology churn, and also the
most invasive — it needs a correctness story for transit-cost changes
that alter PC paths *without* changing any first-hop (the per-x PC
trees must be invalidated on any graph change, not just first-hop
changes).

## 5. SPF worker panic hardening (pre-existing, surface widened)

The `spawn_blocking` JoinHandle is fire-and-forget in both protocols
(`isis/inst.rs` `Message::SpfCalc`, `ospf/inst.rs` both dispatch
sites). A panic inside `compute_spf` loses the `SpfDone` message, so
`spf_inflight` stays latched and SPF is wedged for that level/area
until restart. Pre-existing before this series; the parallel arms keep
panic-free discipline (no unwraps on shared state), but a
`catch_unwind` that always delivers a completion (or clears the latch
via an `SpfFailed` message) is the robust fix. Applies identically to
IS-IS and OSPF.

## 6. Telemetry polish

- OSPF runs one extra x-independent full-path SPF per cycle (its
  primary SPF is nexthop-mode — design doc §13); that SPF is not
  counted in `TilfaStats` (`q_spf`/`pc_spf` don't fit it). Cosmetic:
  add a field or fold it into the rendered line if it ever confuses.
- `Sharding(K)` with `K >` (distinct first-hop count) silently runs at
  group-count width (groups are never split; `width` reports the
  effective value). A debug log on the clamp could help operators
  tuning the `compute-mode sharding shards` count.
- Conservative mode has no BDD scenario (aggressive + sharding are
  exercised live; conservative is pinned by the unit equivalence
  suite). Add one if a regression ever slips through that gap.

## 7. rayon pool sizing knob

The global pool is lazily built at default width (≈ core count) on
first use. If TI-LFA bursts ever contend with tokio workers or other
daemons in production, a one-line `ThreadPoolBuilder::build_global` at
startup (optionally behind a CLI flag / config knob, e.g.
`cores - 2`, named threads for `ps -T`) is the lever. Deliberately not
added until someone observes real contention.

## 8. VRF-aware upper bound

Every VRF instance schedules onto the same global pool — the aggregate
ceiling is the pool width, which is correct for protecting the box but
means one instance's `aggressive` burst can briefly time-share with
another's. If per-instance fairness ever matters, `sharding(K)` per
instance is today's answer; a weighted/prioritized pool would be the
heavier one.
