# BGP peer-task vs update-group egress benchmark

Status: **measured (2026-06-20)**, branch `bgp-egress-group-bench`. Harness:
`tools/bgp-bench/compare-peer-task.sh` over the `bgp-bench` load generator.
Cross-refs: `bgp-peer-egress-task.md` (the PET design + the "OFF wins for RR"
prediction this run refines), `bgp-egress-group-task-migration.md` (the group
task that subsumes both models), `bgp-rib-sharding-plan.md` §9, and
`bgp-sharding-prior-art.md` (the two-axis model: ingress shard vs egress
coalescing).

## 1. Question

For a **large incoming table re-advertised ("reflected") to many peers**, with
**N=4 incoming RIB shards**, which egress model converges faster?

| | gate | egress model |
|---|---|---|
| peer-task **OFF** (default) | `ZEBRA_BGP_PEER_TASK` unset | update-group flush — FRR coalesce-once, replicate bytes to all members |
| peer-task **ON** | `ZEBRA_BGP_PEER_TASK=1` | per-peer egress task (PET) — GoBGP per-goroutine, parallel re-encode per peer |

Both runs set `ZEBRA_BGP_SHARDS=4` so the **ingress** side is identical and only
the egress model differs.

## 2. Method

`compare-peer-task.sh` is a thin A/B orchestrator over `bgp-bench` (the existing
synthetic load generator). For each config it: emits the matching daemon config,
starts `zebra-rs` with the two env gates, runs **one `bgp-bench` measurement**,
captures the single-line JSON (convergence = blast-start → last UPDATE at the
slowest receiver), tears the daemon down, and repeats interleaved over `--reps`.
`bgp-bench` validates correctness itself — a receiver that never sees the full
prefix set reports "DID NOT CONVERGE", so a broken egress model cannot look fast.

**Topology measured:** 4 senders × 200 000 /32s (RIB-FIB ratio 4) → **16 receiver
peers** (the fan-out we "reflect to" and measure), N=4 shards, 3 reps.

**Out-policy** (`emit-config --out-policy`): a permit-all policy doing real work
(`set med` + `as-path-prepend` ×2) is attached to **each receiver**, so the
out-policy *build* — the per-peer egress work the design memo puts at ~75 % of
egress CPU — is on the measured path. Two shapes:

- **shared** — one policy on all 16 receivers ⇒ they share **one** update-group
  (coalescing-favorable; the route-reflector shape the PET memo predicts OFF wins).
- **distinct** — a distinct policy per receiver ⇒ **one update-group each** ⇒
  neither model can coalesce.

**Machine:** 12 cores, 31 GiB RAM, Linux 6.8, release build, `no-fib-install`
(control-plane only; daemon on host loopback — unprivileged userns was disabled).

## 3. Results

```
out-policy = shared  (4 senders × 200k → 16 receivers, N=4 shards, 3 reps)
 config                     converged   conv secs min/med/mean    pfx/s med
 peer-task OFF (upd-group)  3/3         6.504 / 6.515 / 6.950     30 700
 peer-task ON  (per-peer)   3/3         1.915 / 2.106 / 2.149     94 953
 → peer-task ON ~3.1× faster (median 2.106s vs 6.515s)

out-policy = distinct
 config                     converged   conv secs min/med/mean    pfx/s med
 peer-task OFF (upd-group)  3/3        12.362 / 12.708 / 12.659   15 738
 peer-task ON  (per-peer)   3/3         1.853 / 2.123 / 2.102     94 215
 → peer-task ON ~6.0× faster (median 2.123s vs 12.708s)
```

All 16 receivers received the full table in every run (per-receiver `announced`
290k–534k; the surplus over 200k is documented transient best-path flips as the
4 senders' paths arrive during the concurrent blast).

## 4. Analysis

**peer-task ON wins decisively for fan-out convergence, in both shapes.**

At N=4 the v4 Loc-RIB lives in the shard pool and best-path deltas return to the
**main** task. From there:

- **OFF (update-group):** main does the per-prefix attribute **bucketing** and the
  out-policy build/encode runs through a single update-group **flush job** (a
  transient `spawn_blocking` per flush). The encode is coalesced (once per group,
  replicated to members) but the work is gated on main + one flush — it does not
  parallelize across the 16-peer fan-out.
- **ON (PET):** main just fans the best-path delta to 16 **per-peer tasks**, each
  of which runs the out-policy build (`set med` + `as-path-prepend`) and encode
  **in parallel** across the 12 cores.

So the convergence/throughput metric favors parallel-per-peer even in the
**shared** (identical-peer / route-reflector) case — which **refines** the
`bgp-peer-egress-task.md` prediction that OFF wins there. That prediction is
about **CPU/bytes**: OFF coalesces (one encode, fewer UPDATEs), ON re-encodes per
peer and streams more uncoalesced UPDATEs. For one-shot **convergence latency**
on a multi-core box, parallelism beats coalescing-on-main. In **distinct** the gap
widens (OFF degrades to 16 serial flushes, 12.7s; ON is flat at ~2.1s because it
never coalesced anyway).

## 5. Caveats

- **Run large.** The update-group path carries a ~1 s flush/settle floor
  (independent of `adv-interval` — confirmed: `adv-interval 0` keeps it and also
  inflates announce counts by sending transient flips uncoalesced). At 200k it is
  ~15 % of OFF's 6.5 s, not the cause of the 3× gap; at <10k it dominates and the
  comparison is meaningless.
- **Metric is convergence latency / throughput**, not CPU or bytes. A churny
  steady-state route-reflector core with hundreds of *identical* clients may still
  favor OFF on CPU/bytes via coalescing; this is a one-shot bulk-convergence test.
- **Scales with cores.** ON's win is core-bound (16 PETs over 12 cores here).
- The **group egress task** (`bgp-egress-group-task-migration.md`) is the intended
  end-state that gets *both* — coalesce *and* parallelize, at M tasks not N — and
  should beat both models in the shared case; this bench is the baseline to judge
  it against once it lands.

## 6. Reproduce

```sh
cargo build --release -p bgp-bench -p zebra-rs

# shared (coalescing-favorable) — the headline run
tools/bgp-bench/compare-peer-task.sh \
    --senders 4 --receivers 16 --prefixes 200000 --shards 4 \
    --out-policy shared --reps 3

# distinct (diversity-favorable)
tools/bgp-bench/compare-peer-task.sh ... --out-policy distinct
```

Per-run daemon logs and `result.json` are kept under the printed results dir. The
harness emits `transport passive-mode true` on every neighbor (else the daemon's
own outbound dialing collides with the bench's inbound sessions per BGP §6.8 and
resets them once more than ~4 receivers are configured) and runs in a rootless
user+net namespace when available, else on host loopback.
