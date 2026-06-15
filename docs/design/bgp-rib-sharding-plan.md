# BGP RIB Sharding (Juniper-style)

Status: **Phase 0 + A merged; Phase B built at N=1 (sync-dispatch);
policy-parallelism C.1/C.2 built; N-shard dedicated-thread pool +
RouteBatch + mimalloc built; per-shard inbound-policy replication
(`PolicyReplace`) built; Phase E.1 (parallel advertise-outcome
precompute) + E.2 (bounded egress worker pool) built; Adj-RIB-Out
unified across all families (BatchAfi/LabeledAfi)** — Phase 0 + A merged
2026-06-12 (PRs #1402/#1406/#1408/#1416). Everything after Phase A lives
**unmerged** on branch `bgp-nshard-policy-shard` (55 commits ahead of
`main` as of 2026-06-14, no PR yet). Three deliberate divergences from
the §5–8 plan: **B.3 became a synchronous dispatch, not a spawned task**;
**the re-scoped Phase C parallelizes the pure policy walk (rayon)**; and
**the multi-shard fan-out runs on dedicated OS threads, not tokio tasks**.
Shard count is now **runtime env-driven** — `ZEBRA_BGP_SHARDS` (clamp
1–64, default 1), with the egress pool sized by `ZEBRA_BGP_UPDATE_WORKERS`
(default `max(1, cores − shards)`) — the compile-time `SHARDS` constant
is gone; a YANG knob is still the future shipping form.
The "Implementation status" section below is the current architecture of
record; §1–10 remain the original applicability analysis and design
rationale. Open decisions §8: D1 (in-repo `bgp-bench`) and D3
(v4/v6-unicast+LU+VPN scope) resolved as recommended; D2 (channel
boundedness) resolved as **unbounded** for now (both shard inbox and
result channel) — backpressure is a tracked improvement, see §12;
D4 (default shard count) — defaults to 1 (opt-in via env), perf knee
measured at N=4.

Source: "BGP RIB Sharding" — Ravindran Thangarajah, Juniper Networks,
2022-10-24.
<https://community.juniper.net/blogs/ravindran-thangarajah/2022/10/24/bgp-rib-sharding>

## Implementation status (as built — 2026-06-14)

What actually shipped diverges from the §5–8 plan in three deliberate
ways: B.3 became a **synchronous dispatch** rather than a spawned task;
Phase C was **re-scoped** to parallelize the pure policy walk (rayon);
and the multi-shard fan-out (original C.1) runs on **dedicated OS
threads** owning a slice end-to-end, not tokio shard-tasks. On top of
sharding, the egress path was **unified** — every family (v4/v6 unicast,
VPNv4/6, labeled-unicast v4/v6) now has a functional Adj-RIB-Out behind
two generic traits, which is the substrate Phase E.2+ (group-affinity
update-workers) will build on. §5–10 remain the original design
rationale; §11 is the BIRD/GoBGP prior-art comparison and §12 is the
current improvement roadmap.

### Phase B — shard extraction at N=1 (B.1–B.3, built)

- **State partition (B.1).** `BgpShard` (`bgp/shard/mod.rs`) owns the
  sharded Loc-RIB tables — `v4`, `v6`, `v4lu`, `v6lu`
  (`LocalRibTable<…>`) and `v4vpn`, `v6vpn` (`BTreeMap<RouteDistinguisher,
  LocalRibTable<…>>`) — plus the per-peer Adj-RIB-In slices (`adj_in:
  BTreeMap<usize, ShardAdjIn>`), a shard-owned attribute-interning store,
  and `ShardLabelPool` (per-route LU / VPNv4-transit label sub-blocks).
  EVPN / flowspec / SR-Policy / BGP-LS / RTC stay main-owned (§8 D3).
- **Attr store uses ahash** (`store.rs`). A profile put the default
  SipHash at ~28 % of daemon CPU; interned keys are internal dedup keys,
  not attacker-chosen, so a fast non-cryptographic hasher is the right
  trade — it made the converted path net-faster than baseline.
- **B.3 — synchronous dispatch (the pivot).** The plan called for a
  spawned shard task (`BgpShardHandle`, channels). At N=1 a task adds a
  hop + channel overhead and **zero** parallelism (it runs on main's
  core anyway). So B.3 instead routes table ops through
  `BgpShard::handle(ShardMsg, central) -> Vec<ShardOut>`, called
  **inline** from `route.rs`; `shard` is a plain field on `Bgp`, not a
  task. This keeps the value of B.1/B.2 — a clean state partition + a
  typed message protocol, ready to be task-ified for N>1 — without
  paying the task's cost at N=1.
  - `ShardMsg`: `UpdateV4` / `UpdateV6` / `UpdateLu` (+ `WithdrawV4/V6/Lu`,
    `PeerDown`, `Show`, `Shutdown`). `ShardOut`: `BestPathV4/V6/Lu`.
  - Pipeline split per update: **main** runs the per-attr peer checks
    (`inbound_attr_checks`), inbound policy, NHT resolution, and the
    Inter-AS Option-AB transit flag; the **shard** does Adj-RIB-In +
    intern + Loc-RIB insert + best-path + label allocation; **main** then
    acts on the returned best-path delta — NHT untrack, FIB install, VPN
    import/export, advertise.
  - **Dispatch vs direct access (and what is parallelized at N>1)**:
    **only plain v4-unicast fans out across the pool** — via
    `ShardMsg::RouteBatchV4` (one batch per shard, hashed; the message is
    unicast-only, no `rd` field). **VPNv4 deliberately stays on the
    synchronous `bgp.shard`** — its transit label needs main's central
    allocator, which can't be borrowed across the thread boundary, so
    `route_ipv4_update_decided` gates the pool path on `rd.is_none()`
    (`route.rs:2463`). v6-unicast + VPNv6 reach the shard via `UpdateV6`,
    also on the **single synchronous `bgp.shard`** (no `RouteBatchV6` is
    dispatched to the pool yet), and **labeled-unicast (v4/v6) uses direct
    shard-table access** (`bgp.shard.update_v4lu` / `update_v6lu`). So at
    N>1 the only parallelized best-path is plain v4-unicast; VPNv4, v6,
    VPNv6 and LU all stay on the main thread's sync shard. The `UpdateLu` + `WithdrawLu` +
    `Show` + `BestPathLu` variants are wired-but-unused scaffolding for a
    later migration (the dead-code warnings on them are expected).
  - **Live `ShardMsg` set** (`shard/msg.rs`): `UpdateV4`, `RouteBatchV4`,
    `WithdrawV4`, `UpdateV6` (sync only), `PeerDown` (broadcast),
    `SoftInV4` (broadcast), `PolicyReplace` (broadcast),
    `NexthopReachableBatchV4` (batched NHT re-eval). Live `ShardOut`:
    `BestPathV4`, `BestPathV6`.

### Phase C — re-scoped to parallel policy evaluation (C.1/C.2, built)

This is the *re-scoped* C.1/C.2, which landed **first** — parallelizing
the pure policy walk at N=1. (The original-plan C.1, the N-shard
fan-out, landed later as the dedicated-thread pool — see "Phase N-shard"
below and the label note in §6.) The re-scope came from profiling the
N=1 build under a realistic policy-heavy workload (a 1000-entry route-map
applied inbound *and* outbound), which put **74.8 % of CPU in
`PrefixTrie::walk_enclosing`** — the prefix-set match, run ~1000× per
route. Policy evaluation is **pure** (reads the peer's policy snapshot +
the route, mutates nothing) and every prefix in one UPDATE shares one
attribute, so it parallelizes with rayon *without* partitioning the RIB:

- **C.1 — parallel inbound policy.** `route_ipv4_update_batch` runs
  `inbound_attr_checks` once, `par_iter`s the per-prefix policy walk
  (`apply_policy_in_pure`), then writes the Loc-RIB + advertises serially
  in NLRI order.
- **C.2 — parallel outbound policy.** `route_ipv4_update_decided` returns
  advertise jobs instead of advertising inline; the batch then runs three
  phases — serial Loc-RIB updates → **parallel per-group advertise-outcome
  precompute** (`compute_advertise_outcome` is pure) → serial apply
  (cache / adj-out / send in NLRI order). The per-group outcome is
  computed on the same canonical (non-source, non-LLGR) peer the serial
  memo would use, so the result is identical and group-counter bumps stay
  once-per-group.

**Enabling work — family-generic per-peer policy.** The policy engine was
already family-generic (`policy_list_apply_net` takes an `IpNet`,
`PrefixSet::matches` is dual-stack); the in/out apply collapsed into one
core, `apply_policy_net(prefix_cfg, policy_cfg, router_id, IpNet, attr,
weight)`, shared by both directions and all families. Per-peer route-maps
now apply for **v4/v6 unicast, VPNv4/6, and labeled-unicast v4/v6**;
before this only v4-unicast + VPNv4 had them (v6 / LU silently ignored
neighbor policy). Verified by `@bgp_v6_route_map` and `@bgp_lu_route_map`.

### Measured (12-core, 1000-entry policy in+out, 4×100k, interleaved A/B)

| build | convergence | vs serial |
|---|---|---|
| serial (no C.1/C.2) | 19.57 s | — |
| C.1 (parallel inbound) | 11.62 s | −41 % |
| C.2 (parallel inbound + outbound) | **4.34 s** | **−78 % (4.5×)** |

The win is the policy walk; the §9 baseline matrix (no policy) is a
different workload where this parallelism barely registers — there the
planned multi-shard / update-worker fan-out is what pays.

### Phase N-shard — dedicated-thread pool (as built, env-gated, default off)

The planned multi-shard fan-out (original C.1) is now built, but on
**dedicated OS threads, not tokio tasks or rayon** — the rayon-per-UPDATE
form (the re-scoped C.1/C.2 above) regressed the no-policy workload ~36 %
(a `par_iter` tax with no policy to amortize), so the shard became a real
thread that owns its slice end-to-end.

- **`ShardPool`** (`bgp/shard/pool.rs`) spawns `shard_count()` worker
  threads (`std::thread`, named `bgp-shard-{idx}`), one per `BgpShard`. A
  worker blocks on a `std::sync::mpsc` inbox, runs `BgpShard::handle`, and
  ships a `ShardResult` back over a tokio `UnboundedSender`. CPU-bound work
  on real threads keeps it off the tokio runtime and away from the I/O
  (reader/writer) tasks.
- **`shard_count()`** (`inst.rs`) reads `ZEBRA_BGP_SHARDS`, clamps to
  `1..=64`, defaults to 1 — runtime env-driven, no compile-time constant.
  (The shipping form is a YANG knob, §12.)
- **`shard_of(addr)`** = FNV-1a over the address octets `% N`
  (deterministic, address-only) so unicast / LU / VPN rows of one prefix
  co-locate (the Juniper invariant) with no cross-shard synchronization.
- **Gated on `shard_count() > 1`** (`inst.rs`): at the default `1`
  nothing spawns (`(n_shards > 1).then(…)`), the synchronous `shard` field
  + byte-identical sync path run, and the event loop's `shard_results_rx`
  arm stays idle — so BDD and every default run traverse the proven N=1
  path.
- **RouteBatch** (`ShardMsg::RouteBatchV4`): one UPDATE's prefixes are
  split by hash and sent as **one batch per shard** (not one message per
  prefix), collapsing ~4M per-prefix futex wakeups to ~N.
- **Phase C — policy in the shard** (`compute_policy: true`): the shard
  runs inbound policy itself, removing main's `par_iter`.
- **mimalloc** as the global allocator (`main.rs`): per-thread heaps
  remove ~12 % of CPU an N=12 profile put in the allocator's `osq_lock`
  (shards intern attrs / build RIB rows concurrently).
- **Reduce** (`inst.rs::process_shard_result`): the main event loop
  `select!`s best-path deltas and runs NHT untrack + FIB install +
  advertise off each.

**Measured (12-core, no-policy 8×500k, interleaved A/B, NHT release
batched).** Isolation showed the shard *dispatch* is free (sync-dispatch ≈
baseline) and ahash interning even helps (−11 %); naive sharding then
regressed the workload (ungated rayon par_iters +46 %, per-prefix dispatch
storms, allocator contention), which RouteBatch + mimalloc + uniform
cost-gating of every rayon par_iter (C.1 inbound, C.2 outbound, E.1 reduce)
+ per-shard NHT-release batching all fixed. End state, `ZEBRA_BGP_SHARDS`
swept (one binary, no recompile):

| build | r1 | r2 | r3 | avg | vs base |
|---|---|---|---|---|---|
| base (pre-sharding) | 20.89 | 20.79 | 20.51 | 20.73 s | — |
| N=1 | 15.62 | 16.53 | 16.66 | 16.27 s | −22 % |
| N=4 | 14.94 | 14.12 | 14.25 | 14.44 s | **−30 % (knee)** |
| N=12 | 16.62 | 16.66 | 16.55 | 16.61 s | −20 % |

**N=4 is the sweet spot; N=12 over-shards** — a textbook optimal-thread
curve (Juniper's "threads ≤ cores", gains evaporating past the knee). At
SHARDS ≈ cores there are no spare cores for the main reduce + tokio I/O, so
coordination outweighs the marginal best-path gain on a workload where
per-route work is trivial. The wins here are mostly ahash + mimalloc +
de-taxing the par_iters; the shard fan-out adds −22 %→−30 % from N=1 to the
N=4 knee, then regresses. (The earlier −23 % at N=12 was *before* the N>1
NHT-release fix, when first-sight held routes were silently stuck — these
numbers are correct end-to-end, and batching the release collapsed the N=12
run-to-run spread from ~1.4 s to ~0.1 s.) It pays far more under policy
(C.1/C.2 above; E.1 −39 % at N=12) or high RIB-FIB fan-out (§9).

### Phase E — parallel advertise (the reduce is the next serial point)

At N>1 the shards parallelize best-path, but the **reduce**
(`process_shard_result`) still ran the advertise — out-policy + attribute
transform + bucketing — serially on the main thread (it passed an *empty*
memo, so `compute_advertise_outcome` ran inline). That is exactly the C.2
parallelism *lost* when ingest moved to the shards. The encode itself is
already off-thread (Phase A `FlushJob` → `spawn_blocking`); Phase E moves
the rest of egress off the serial reduce.

- **E.1 (built) — parallel advertise-outcome precompute in the reduce,
  cost-gated.** `route_apply_bestpath_v4_batch` runs NHT untrack + FIB
  install serially over a whole `ShardResult`, then — **only when an
  out-policy is bound on some advertised-to peer** — `par_iter`s the
  per-(prefix, group) out-policy + attribute transform
  (`precompute_ipv4_advertise_outcomes`, the C.2 routine), then applies
  the bucketing serially off the memos. Measured at N=12 (interleaved A/B
  vs the pre-E.1 N=12 build): policy-heavy 8×100k convergence
  **18.97 s → 11.65 s (~39 %)**. The cost-gate is essential: at
  SHARDS ≈ cores there are no spare cores, so an *ungated* par_iter steals
  them from the CPU-bound shard threads — a no-policy 8×500k load
  regressed **3.2×** (15.7 s → 50.8 s) before the gate. Parallelize egress
  only when out-policy makes egress the bottleneck (the shards are then
  mostly idle); otherwise the serial inline apply (byte-identical) keeps
  every core on best-path. The general fix for the *both-busy* case
  (out-policy + saturated shards, e.g. post-`PolicyReplace`) is E.2's
  bounded worker pool, not rayon's cores-wide global pool.
- **E.2 (built) — bounded egress worker pool.** E.1's out-policy precompute
  now runs on a **bounded** rayon `ThreadPool` (`egress_pool().install(…)`)
  instead of rayon's cores-wide *global* pool, so it can't oversubscribe
  the dedicated shard threads at N ≈ cores. Sized from
  `ZEBRA_BGP_UPDATE_WORKERS`, default `max(1, cores − ZEBRA_BGP_SHARDS)` —
  which makes the **shard count the cores-split knob** (Juniper's
  shards-vs-update-threads): inbound parallelism from the shards, outbound
  from the egress pool, the two *fitting* the core count rather than
  fighting for it. Measured (1000-entry policy in+out, 8×100k): serial
  baseline 42.7 s; **N=4 (4 shards + 8 egress) 8.9 s (−79 %)**, beating the
  old oversubscribed global-pool N=12 (11.9 s) by ~25 %. N=12 starves egress
  (=1 worker → serial out-policy walk) at 20.9 s — the "no spare cores"
  reality made explicit, and why the optimum is N=4, not N=cores.
- **E.2+ (future) — group-affinity update-workers.** The full Juniper form:
  move the per-group caches + adj-out + encode into M dedicated worker
  threads with static group→worker affinity, fed `AdvDelta` (RTO) directly
  by the shards (bypassing the main reduce). BIRD 3.x (a per-protocol loop
  pulls a lockfree journal, then filters + encodes on its own thread) and
  GoBGP (a per-peer send goroutine) are the two reference designs (§11).
  Per-(peer, prefix) ordering holds: one prefix → one shard → one worker.

### Adj-RIB-Out unification — the egress substrate (built)

Independent of the shard split but built on the same branch, the egress
path was unified across all families. This matters here for two reasons:
the shard reduce now drives **one** advertise path regardless of family,
and E.2+ (group-affinity workers fed `AdvDelta`) needs a per-family
Adj-RIB-Out to diff against — which only v4/VPNv4 had before.

- **Phase 1 — functional Adj-RIB-Out for v6 / LU / VPNv6.** Before this,
  v4-unicast and VPNv4 stored a real per-peer Adj-RIB-Out (`Peer.adj_out`,
  the `AdjRib<Out>` in `adj_rib.rs`) and pruned withdrawals against it;
  v6, labeled-unicast (v4/v6) and VPNv6 **flooded every withdrawal to
  every Established peer** with no per-peer egress state, which produced a
  withdraw ping-pong (a route a peer was never sent still got a withdraw,
  bouncing back). The interim ping-pong guards (`64f205b6` v6, `d7f048fe`
  LU, `c12d675f` VPNv6) were removed once each family got a real
  `adj_out` slice (`adj_out.{v6,v4lu,v6lu,v6vpn}`) — a peer not in the
  table is simply never sent a spurious withdraw, so the bug class is
  **structurally** gone.
- **Phase 2 — generic advertise via two traits.** The per-family
  `route_advertise_to_peers_{v4,v6,vpnv4,vpnv6}` functions collapsed into
  one `route_advertise_batch::<A: BatchAfi>` (impls `V4Batch` / `V6Batch`,
  covering v4/v6 unicast + VPNv4/6), and the labeled-unicast pair into one
  `route_advertise_labeled::<A: LabeledAfi>` (impls `LabeledV4` /
  `LabeledV6`). The `BatchAfi` trait carries `compute_outcome` (the pure
  out-policy + attribute transform the E.1/E.2 reduce parallelizes),
  `advertise`, `withdraw`, `advertise_addpath`; `LabeledAfi` carries the
  per-peer `adj_out_*` diff primitives plus `update`/`apply_policy_out`.
- **AddPath — advertise all candidates** (`3a27ec65`): the event-driven
  v6 and LU AddPath paths now read the **full Loc-RIB candidate set** from
  the shard (`bgp.shard.v6.0.get(prefix)` / `A::all_cands`) instead of the
  best-only `selected` (≤1 path), which silently dropped non-best AddPath
  candidates on the event path. v4/VPN already advertised per-candidate.

The update-group cache (`cache_ipv4` …) and `UpdateGroupSig` are
unchanged — the signature is per-session, not per-family, so unification
needed no new variants.

### Still future (immediate sharding gaps)

- **VPNv4 / v6 / VPNv6 / LU pool dispatch.** At N>1 only plain v4-unicast
  fans out; VPNv4, v6, VPNv6 and LU best-path still run on the single sync
  shard. VPNv4 needs a pool path that keeps label allocation shard-side
  (today its transit label borrows main's central allocator); v6/VPNv6
  need `RouteBatchV6`; LU needs the `UpdateLu`/`WithdrawLu` scaffolding
  activated.
- **N>1 barriers** (planned C.3): EoR / route-refresh / GR-LLGR sweeps
  must become broadcast-and-ack across shards.
- **N>1 v4-unicast read paths** (B.4) — **critical**: `show bgp ipv4`,
  session-up `route_sync_ipv4`, and `clear`/soft-in all read the
  synchronous `bgp.shard.v4`, which is empty at N>1 (v4-unicast is the only
  pooled family and the reduce never mirrors best-paths back). The operator
  can't see the v4 RIB and a peer establishing after routes exist gets
  nothing; forwarding is unaffected. (The earlier "`Show` is wired" note was
  wrong — disproved by `@bgp_shard_v4_sync`.) Fix plan + recommended design
  below.
- **YANG knob** `router bgp shards <1-64>` to replace `ZEBRA_BGP_SHARDS`
  as the shipping form (planned C.4), plus the perf matrix + default.
- **`PolicyReplace` correctness sweep.** Inbound policy snapshots are now
  replicated to shards (`BgpShard.in_policy`, broadcast `PolicyReplace`);
  remaining work is the live-reconfig re-evaluation path (re-running
  best-path against the new snapshot, not just storing it).

The larger architectural improvements — drawn from the BIRD/GoBGP study
(§11) — are collected in §12.

### Read-path scatter-gather at N>1 — bug + fix plan (B.4)

**Bug (critical, v4-unicast-only).** At N>1, plain v4-unicast best-paths
live only in the pool shards; the reduce (`reduce_bestpath_v4_nht_fib`)
does FIB-install + advertise off the delta and never populates the
synchronous `bgp.shard.v4`. So every read path that consults it returns
empty: `show bgp ipv4`, the session-up dump `route_sync_ipv4`, and
`clear`/soft-in. The operator can't see the v4 RIB, and a peer that
establishes *after* routes exist receives only the EoR marker. Forwarding
is unaffected (event-driven advertise runs off the delta). Locked by the
`@bgp_shard_v4_sync` BDD (red until fixed): an early peer learns routes via
the event-driven path (control, green), a late peer gets nothing on sync
(bug, red), and the sharded node's own `show bgp ipv4` is empty (bug, red).

**The work to parallelize.** A full dump/show is not bounded by *reading*
the RIB — it is the per-route egress build: `route_update_ipv4`
(next-hop-self, AS_PATH), the out-policy `PrefixTrie::walk_enclosing` (the
profile's 74.8 %-of-CPU hot spot), intern, encode. For a route reflector
that is millions of routes per new peer. *Where that build runs* decides
whether the fix scales on a multi-core box.

**Options.**

- **A1 — gather-then-build.** Shards return raw `(prefix, BgpRib)` rows;
  main assembles and runs the egress build serially. Correct, but the build
  is back on one core and every row is copied main-ward (an N→1 funnel) — it
  reintroduces the single-core ceiling Phase E removed.
- **A2 — shards build and send their own slice (RECOMMENDED).** A per-
  session `SyncCtx` snapshot (local addr for next-hop-self, peer_type/AS,
  AddPath flag, out-policy snapshot — already shard-replicated via
  `PolicyReplace` — ENHE, the cloneable `packet_tx`) rides the request;
  each shard transforms + out-policy-filters + encodes + sends *its own*
  slice directly to the peer, in parallel across all N shard cores with
  full data locality (no gather copy). Main only emits EoR after an N-ack
  barrier (the C.3 broadcast-and-ack). This is the E.2+
  shards-as-update-workers model applied to the read path; it is the only
  option that makes the dump scale ~N-way and the only one that reads the
  cands table for AddPath. One `DumpV4` then serves `show`, `sync`, and
  `clear` alike.
- **B — main best-path mirror.** The reduce also writes `selected` into
  `bgp.shard.v4`; reads stay synchronous. Tiny, but the build is still
  serial on main, AddPath sync stays best-path-only, and it reintroduces a
  FIB-sized v4 copy + an always-on mirror-consistency invariant — the exact
  bug-class sharding removed.

**Recommendation: A2** — the only fully-correct *and* scalable fix: the
expensive egress build fans out across the shard cores instead of
funnelling back to one. A1/B are correct-but-serial (a single-PR stop-gap
at best). Multi-core scalability ranking: **A2 ≫ A1 ≈ B**.

Tradeoff: A2 packs UPDATEs per-shard, so same-attribute routes in different
shards (the attribute is not the hash key) ride separate MP_REACH messages
— marginally more packets, dominated by the N-way CPU win on any large
dump. Caveat (E.2's lesson): at N ≈ cores a sync burst building in the
shards competes with steady-state ingest; if it starves ingest, route A2's
build through the bounded `egress_pool()` rather than rayon's global pool.

**PR breakdown (A2):** ① `ShardMsg::DumpV4 { SyncCtx }` + `DumpDoneV4` ack +
a per-request barrier (N=1 keeps today's direct read) → ② shard
`handle_dump_v4`: walk the slice, build + send per `SyncCtx` → ③ wire `show
bgp ipv4` through it (flips the z2 assertion green) → ④ wire
`route_sync_ipv4` through it (flips z4 green; add an AddPath-send BDD
variant) → ⑤ retrofit `clear`/soft-in onto the same `DumpV4`.

## 1. Verdict

Juniper's BGP RIB sharding is applicable to zebra-rs — and zebra-rs is
structurally better positioned for it than RPD was. Juniper's design
principle is "no locks, message passing, per-thread state ownership,
eventual consistency", which is already zebra-rs's native idiom (tokio
tasks + channels). The applicable form is **shard tasks partitioned by
prefix hash + update-worker tasks fed by the existing update-group
caches**, with the existing single event loop retained as the
session/coordination task.

Several of the hardest centralization problems Juniper had to solve
(resolver service, FIB download, cross-protocol active-route selection)
already exist in zebra-rs as channel-based services, because BGP is
decoupled from the central RIB daemon. The real cost is not concurrency
machinery — it is partitioning the `Bgp` struct's state into
shard-owned / replicated / main-only classes.

## 2. What Juniper built

Two thread families, plus the legacy main thread:

- **Shard threads (S1..Sn)** — the RIB is sliced by *hash of the prefix
  address*. Each shard owns its slice end-to-end: inbound flash,
  policy, best-path selection — a "mini eco-system" with per-thread
  state and zero cross-shard synchronization. Non-BGP routes are hashed
  into shards too, so *every* route for a given prefix lives in exactly
  one shard.
- **Update threads (U1..Um)** — shards do not emit UPDATE messages
  directly (that would fragment packing across shards). They emit
  **Route Tuple Objects (RTO)** — prefix + attribute shorthand — and
  update threads merge RTOs from all shards into efficiently packed
  per-group UPDATEs.
- **Main thread** — anything needing a centralized view: nexthop
  resolution ("resolver as a service" consumed by shards), conditional
  policy, IGP export, FIB download (KRT).

Published results: ~9x convergence on a 24-core route reflector (8M
routes in / 800M out), 3.5–4x on peering/flap scenarios, 2.5x on a
4-core edge box. Gains scale with the **RIB-FIB ratio** (paths learned
per unique prefix) and outbound fan-out; they evaporate when per-prefix
main-thread work (FIB install) dominates or route scale is small.
Optimal thread count <= CPU cores.

## 3. Where zebra-rs is today — the unit of serialization

The entire route-processing pipeline runs in one tokio task
(`event_loop`, `zebra-rs/src/bgp/inst.rs:2959`). What is already
parallel and what is not:

| Stage | Today | Where |
|---|---|---|
| Wire parse | parallel, per-peer reader tasks | `bgp/peer.rs:2065`, `peer_packet_parse` |
| Policy-in, attr intern, Adj-RIB-In | serialized in main loop | `bgp/route.rs:2185-2201` |
| Loc-RIB insert + best path | serialized | `bgp/route.rs:990`; `select_best_path` at `bgp/route.rs:1039` |
| NHT gate / re-election storms | serialized | `set_nexthop_reachable` sweep |
| VRF import/export fan-out | parallel, per-VRF tasks, channel-based | `vrf_emit_export` / `dispatch_import_v4`, `bgp/route.rs:2258-2294` |
| Advertisement bucketing | serialized | group caches, `bgp/update_group.rs:181` |
| UPDATE encode | serialized (but already **once per group**, replicated to members) | `bgp/update_group.rs:640-667` |
| TCP write | parallel, per-peer writer tasks | `bgp/peer.rs:2075` |

The pipeline is parallel at both ends and single-threaded in the
middle. One core is the convergence ceiling regardless of machine size.

## 4. Structural mapping — why this fits unusually well

| Junos concept | zebra-rs counterpart | Status |
|---|---|---|
| Shard thread owning a RIB slice | `BgpShard` owning `LocalRibTable<P>` partitions + adj-in slices (a plain field at N=1, a dedicated OS thread per shard at N>1 — *not* a tokio task) | ✅ built — only plain v4-unicast fans out across the pool; VPNv4 (transit label needs main's central allocator), v6, VPNv6 and LU best-path still run on the single sync shard. The per-VRF task (`process_vrf_global_msg`) was the precedent, sharded by table instead of by hash |
| RTO (prefix + attr shorthand) | `(Arc<BgpAttr>, Nlri, source_ident)` — the *existing* update-group cache entry (`bgp/update_group.rs:181`) | exists — zebra-rs invented the RTO without naming it |
| Update thread packing RTOs | update-worker task owning `UpdateGroup` caches + debounce timers + canonical encode | 🔶 partial — encode is off-thread (A.2 `FlushJob` → `spawn_blocking`) and the out-policy precompute parallelizes (E.1/E.2 bounded egress pool); the dedicated group-affinity worker fed `AdvDelta` is still future (E.2+, §12) |
| Resolver-as-a-service in main | already a service: RIB daemon NHT over `RibRx::NexthopUpdate` channel | exists |
| Non-BGP routes hashed into shards | **not needed** — cross-protocol active-route selection lives in the central RIB daemon, not in BGP | simpler than Junos |
| KRT/FIB download from main | `rib_client` channel sends — handle is cloneable into shards | exists |
| Cross-task attribute transfer | `BgpVrfMsg::ImportV4 { attr: BgpAttr, .. }` — attr by value, receiver re-interns into its own `BgpAttrStore` (`bgp/vrf/msg.rs:37-40`) | convention already established |
| Per-thread state localization | Rust ownership — the compiler enforces the partition RPD had to maintain by discipline | advantage |

## 5. Target architecture (end state)

```
peer reader tasks ──Event──▶ ┌──────────────┐
                             │  main task   │  FSM, config, show fan-out,
peer writer tasks ◀──bytes── │ (coordina-   │  listeners, VRF registry,
        ▲                    │  tion)       │  NHT RIB-facing session,
        │                    └──┬───────┬───┘  FIB install, small tables
        │            RouteBatch │       │ control (policy / peer events /
        │            (per-NLRI  │       │ NHT replicas / refresh / sync)
        │             hash)     ▼       ▼
        │                  ┌────────┐ ┌────────┐
        │                  │shard 0 │…│shard N │  policy-in, adj-in slice,
        │                  └──┬─────┘ └──┬─────┘  Loc-RIB slice, best path,
        │           AdvDelta  │          │        VPN import/export emit
        │           (RTO)     ▼          ▼   FibDelta ──▶ main ──▶ RIB
        │                  ┌────────────────┐
        └──── encoded ──── │update workers  │  per-group transform, bucket,
              UPDATEs      │ 0..M (group    │  debounce, canonical encode,
                           │  affinity)     │  adj-out
                           └────────────────┘
```

- **Shard ownership**: v4/v6 unicast, v4/v6 labeled-unicast, VPNv4/v6
  tables, plus the per-(peer, prefix) adj-in slices for those tables.
  Hash on the *inner* prefix address only, so unicast/LU/VPN instances
  of one prefix co-locate (Juniper's invariant).
- **Stays in main**: `PeerMap` + FSM, listeners/accept, config/show
  dispatch, `nexthop_cache` (RIB-facing registration; shards hold
  replicas), FIB emission, VRF registry + label/SID allocators,
  redistribute snapshots, and the small tables: EVPN, flowspec,
  SR-Policy, BGP-LS, RTC, table-map.
- **Replicated into shards** (broadcast on change): policy snapshots,
  NHT entries (reachability + resolved transport), import-RT sets from
  `rib_known_vrfs`, VRF inbox senders, per-shard label sub-blocks.
- **Per-VRF tasks** stay as the outer dimension, single-shard initially.

## 6. Step-by-step delivery plan

Each PR is a separate branch off `main` (repo convention), lands only
CI-green, and must leave the daemon fully functional — sharding ships
off by default (`ZEBRA_BGP_SHARDS` unset → N=1) until C.4 flips a YANG
knob. Status column reflects the `bgp-nshard-policy-shard` branch (all
post-A rows unmerged as of 2026-06-14).

| Step | Title | Depends on | Status |
|---|---|---|---|
| 0.1 | Bench harness + baseline profile | — | merged (PR #1406) |
| A.1 | Flush job extraction (pure function) | — | merged (PR #1408) |
| A.2 | Flush offload to worker | A.1 | merged (PR #1416) |
| B.1 | State partition: `BgpShard` struct, adj-in re-keying | — | ✅ built (WIP branch) |
| B.2 | Shard message protocol + label sub-blocks | B.1 | ✅ built (WIP branch) |
| B.3 | ~~Spawn shard task~~ → **sync dispatch** at N=1 | B.2 | ✅ built — pivoted to sync, see "Implementation status" |
| B.4 | Show / clear / sync scatter-gather | B.3 | ❌ not built — `show` / `sync` / `clear` all read the empty `bgp.shard.v4` at N>1 (`@bgp_shard_v4_sync` red); recommended A2 fix plan in Implementation status |
| B.5 | BDD + lifecycle hardening at N=1 | B.4 | ⏳ |
| C.1 | Prefix-hash fan-out to N shards (+ YANG knob) | B.5 | ✅ built — dedicated-thread `ShardPool`, env-gated `ZEBRA_BGP_SHARDS` (plain v4-unicast only; VPNv4/v6/VPNv6/LU still sync); YANG knob still future |
| C.2 | Update-worker tasks (group affinity) | A.2, C.1 | 🔶 partial — E.1/E.2 parallel egress (bounded pool) built; dedicated group-affinity workers = E.2+ (§12) |
| C.3 | Barriers: EoR, refresh, GR/LLGR sweeps, clear | C.1 | ⏳ |
| C.4 | Perf matrix, defaults, docs | C.2, C.3 | ⏳ |

> **Phase C label note**: "C.1/C.2" name two different axes. The
> *re-scoped* C.1/C.2 (rayon-parallel inbound/outbound **policy** at N=1)
> built first; the *original-plan* C.1 (multi-shard fan-out) then landed
> as the dedicated-thread `ShardPool`, and the original-plan C.2
> (update-workers) is partly covered by E.1/E.2's parallel egress with
> the dedicated group-affinity form deferred to E.2+ (§12). The rows
> above track the original-plan axis.

### Phase 0 — Baseline measurement (before touching anything)

**0.1 — Bench harness + baseline profile.**
A load generator that opens N BGP sessions against zebra-rs, blasts M
routes (reusing the `bgp_packet` crate for encoding), and measures
(a) time-to-Loc-RIB-quiescence and (b) time-to-readvertise on a
listening session. Plus a documented flamegraph recipe for the main
task under load. Record baseline numbers in this doc.
*Why first*: Juniper's gains depend on where time actually goes
(policy/best-path vs encode/fan-out vs allocations). The profile sizes
expectations, picks Phase C defaults, and is the regression gate every
later step must pass.
*Exit*: baseline table in §9; harness runnable by CI on demand (not in
the default suite).

### Phase A — Update-flush offload (independent of sharding)

**A.1 — Flush job extraction.**
`flush_ipv4` (`bgp/update_group.rs:492`) already drains buckets and
snapshots `MemberCtx { ident, packet_tx, enhe_v6, llgr_ok }` before
encoding — make that split explicit: a `FlushJob` value (buckets,
member ctxs, `max_packet_size`, sig-derived consts) and a pure
`run(job) -> (per-member byte batches, counter deltas)`. Main still
runs it inline. Same for `flush_ipv6`.
*Tests*: golden byte tests pinning canonical + pruned UPDATE encodings
(per attr-bucket, with/without split-horizon sources, LLGR exclusion,
ENHE per-member next-hops). No behavior change.

**A.2 — Flush offload.**
Execute `FlushJob::run` on `tokio::task::spawn_blocking` (the IS-IS
SPF offload precedent). Bytes go straight to the snapshotted
`packet_tx` senders from the worker; counter deltas return via a new
`Message::FlushDone(group_id, deltas)`. Invariant: **at most one
in-flight flush per group** — a `flush_inflight` flag on `UpdateGroup`;
routes queued during flight re-arm the debounce timer on `FlushDone`.
*Tests*: A.1 goldens unchanged; BDD suite green; bench shows main-loop
headroom on a fan-out workload (many members, large table).

### Phase B — Shard extraction at N=1 (the real refactor, race-free)

**B.1 — State partition (mechanical, single task, no behavior change).**
Introduce `struct BgpShard` and move the shard-owned state into it:
`local_rib.{v4,v6,v4lu,v6lu,v4vpn,v6vpn}`, a shard-side
`BgpAttrStore`, and adj-in. Adj-in today lives on `Peer`
(`peer.adj_in.add`, `bgp/route.rs:2187`) — re-key it into the shard as
`ident -> AdjRib` slices, since `Peer` stays main-owned. The existing
`BgpInstCtx` borrow-bundle (`bgp/inst.rs:2940-2953`) becomes the seam:
split it into a `ShardCtx` (everything `route.rs` functions may touch)
and main-only context; re-home the `route.rs` entry points to take
`&mut BgpShard`. The compiler does the audit — any route-path access
to main-only state becomes a build error to resolve deliberately.
EVPN/flowspec/SR-Policy/BGP-LS/table-map explicitly stay outside
`BgpShard` (see §8 D3).
*Likely splits during review*: adj-in re-keying (B.1a) vs `ShardCtx`
extraction (B.1b). Largest mechanical PR of the series.
*Tests*: full suite + A.1 goldens; zero functional delta.

**B.2 — Shard message protocol + per-shard label sub-blocks.**
Model on `bgp/vrf/msg.rs` (the documented precedent):
- `ShardMsg` (main → shard): `RouteBatch { ident, afi_safi, attr,
  nlris }`, `WithdrawBatch`, `PeerUp { ident }` / `PeerDown { ident }`
  (flush + adj-in clear), `Originate`/`Deoriginate` (network +
  redistribute + BGP-LS-independent local routes), `PolicyReplace`,
  `NexthopUpdate`, `RtSetsUpdate`, `VrfInboxUpdate`, `SyncPeer { ident,
  afi_safi }` (Established walk / soft-out), `Refresh { ident, op }`
  (soft-in replay), `Show(DisplayRequest)`, `Shutdown`.
- `ShardOut` (shard → main): `FibDelta { table, prefix, selected }`,
  `NhtTrack`/`NhtUntrack`, `AdvDelta { afi_safi, prefix, best,
  source_ident }` (the RTO — consumed by main's existing advertise
  path until C.2), `LabelBlockLow` (sub-block refill request).
- VPN import/export emit **directly** from shard to VRF inboxes /
  from VRF tasks into the owning shard — the channel handles are
  clones; no main hop.
- Label allocation (`lu_label_*`, `vpn_label_v4` — consulted in the
  hot path at `bgp/route.rs:2223`) cannot RPC to main per route:
  carve the RIB-granted dynamic block into per-shard sub-blocks;
  shards allocate locally and request refills via `LabelBlockLow`.
*Tests*: unit tests on the protocol types + sub-block allocator;
doc-comment the ordering contract (§7).

**B.3 — Spawn the shard task (N=1).**
Mirror `spawn_bgp_vrf` (`bgp/vrf/spawn.rs:115`): `BgpShardHandle
{ inbox, show_tx, task }`. Main relays `FsmEffect::RouteUpdate`
packets as `RouteBatch` (attrs already parsed by reader tasks);
shard runs policy-in → intern → adj-in → Loc-RIB → best path → NHT
gate, emits `FibDelta` (main installs via `fib_install_*`, keeping
table-map/color/flex-algo consultation in main) and `AdvDelta` (main
feeds today's `route_advertise_to_peers` bucketing). Peer
up/down/refresh relayed as control messages. Centralize the per-peer
sweep into one `route_clean(ident)` API on `BgpShard` covering every
sharded AFI/SAFI — this structurally closes the "new SAFI must
remember to add a route_clean block" bug-class (#1329).
*Tests*: full BDD suite (the real gate — every BGP feature traverses
the split); targeted unit tests for the relay path.

**B.4 — Show / clear / sync scatter-gather.**
Route-table show commands move to the shard show channel, reusing the
`SubscribeShowVrf` redirect recipe (`BgpVrfHandle::show_tx`); summary/
neighbor shows stay main. `clear bgp` soft-in replays adj-in inside
the shard; soft-out re-runs `SyncPeer`; hard clear = `PeerDown` +
session reset.
*Tests*: BDD show/clear features; `parse()` pin tests for any show
spelling that moves.

**B.5 — Lifecycle hardening + BDD at N=1.**
A dedicated BDD feature: peer flap under continuous route churn,
route-refresh mid-stream, EoR timing, GR/LLGR stale sweep — asserting
no leaked routes after teardown (the §7 ordering contract in action).
*Exit for Phase B*: full BDD green at N=1; bench parity with baseline
(no regression beyond noise); this doc updated with measured relay
overhead.

### Phase C — N shards + M update-workers (the Juniper form)

**C.1 — Prefix-hash fan-out.**
`shard_of(prefix) = hash(inner prefix address) % N` — stable across
AFI/SAFI so LU/VPN/unicast rows of one prefix co-locate. Main splits
each `RouteBatch` per shard (hash + Vec push only — the heavy work is
already shard-side); control messages broadcast to all shards;
`SyncPeer` fans out and each shard walks its slice. YANG knob `router
bgp shards <1-64>` (default 1), applied at instance (re)start only —
live resharding is out of scope. NHT: main refcounts `NhtTrack`/
`NhtUntrack` across shards, keeps the single RIB-facing registration,
broadcasts `NexthopUpdate` replicas.
*Tests*: BDD variants of an existing multi-peer feature at shards=2
and 4; unit test: hash stability + co-location property.

**C.2 — Update-worker tasks.**
Move `UpdateGroupMap` ownership + the Phase A `FlushJob` machinery
into M worker tasks with **static group → worker affinity**. Shards
send `AdvDelta` directly to the owning worker (bypassing main).
Workers own the per-group transform (Phase 2 memo code), bucketing,
debounce timers, encode, and adj-out for their groups' members; main
broadcasts membership/sig snapshots on regroup and peer Established.
Per-(peer, prefix) ordering holds: one prefix → one shard → FIFO to
the one worker owning the group.
*Interaction*: update-groups design Phase 4 (dynamic regroup) becomes
a main → worker broadcast; land #4 first or fold it in here — decide
at review time.
*Tests*: A.1 goldens re-pinned at the worker boundary; BDD soft-out /
advertised-routes features.

**C.3 — Barriers and lifecycle at N>1.**
EoR emission waits on all shards' sync completion (broadcast-and-ack);
route-refresh and GR/LLGR stale sweeps likewise ack-gated; hard clear
drains per-shard queues before session restart. Chaos test in the
bench harness: peer churn under full-table load at shards=4, asserting
Loc-RIB/adj-out consistency afterward.

**C.4 — Perf matrix + defaults.**
Re-run the Phase 0 matrix across shards × update-workers × peers ×
routes (Juniper's table as the template). Record results in §9; pick
the shipping default (stay 1 unless the numbers argue otherwise —
Juniper's data says gains need RIB-FIB ratio and fan-out we should
prove on our own workloads). Update `docs/` + book page; only then
consider flipping the default.

## 7. Correctness invariants

- **Single-relay FIFO ordering (v1)**: main is the *only* producer
  into each shard channel, and relays in FSM order — so `RouteBatch`,
  `PeerDown`, `PeerUp`, `Refresh` for one peer arrive in exactly the
  order main processed them. No epochs needed while this holds.
  Anything that later bypasses main (e.g. reader-direct dispatch, a
  listed follow-up) **must** introduce per-peer session epochs and
  shard-side stale-epoch drops.
- **Per-prefix ordering**: one prefix → one shard (hash affinity) →
  one update-worker (group affinity) → per-peer writer FIFO.
  Cross-prefix reordering is acceptable — that is the eventual
  consistency BGP already tolerates and Juniper's design leans on.
- **One in-flight flush per group** (from A.2) — preserves
  announce/withdraw ordering within a group.
- **Broadcast-and-ack barriers** for EoR / refresh / GR sweeps (C.3):
  a barrier may not be declared done until every shard acked.
- **Update-group signature discipline** is unchanged and is what makes
  update-workers safe — the risk register in `bgp-update-groups.md` §6
  (silent leak, capability mismatch) applies identically.

## 8. Decisions (resolved)

All four were ruled as recommended and are reflected in the current
build (see the Status header): **D1** in-repo `bgp-bench` (PR #1406);
**D2** channels unbounded both directions for now, with backpressure
tracked as §12 P2; **D3** v4/v6-unicast + LU + VPNv4/6 sharded,
EVPN/flowspec/SR-Policy/BGP-LS/RTC main-owned; **D4** default shard
count 1 (opt-in via `ZEBRA_BGP_SHARDS`), measured knee at N=4. The
original framing of each follows.

- **D1 — Bench harness form (Phase 0.1)**: in-repo Rust injector
  reusing `bgp_packet` (recommended — no new system deps, CI-runnable)
  vs driving GoBGP/exabgp from the BDD harness (less code, heavier
  environment, poor encode-rate control).
- **D2 — Channel boundedness (B.2)**: recommend matching the VRF
  precedent — unbounded both directions (`vrf_global_tx` style) to
  rule out main↔shard send-deadlock, revisit backpressure after C.4
  numbers. Alternative: bounded data channels with `try_send` +
  overflow accounting.
- **D3 — Sharded-table scope (B.1)**: recommend v4/v6 unicast + LU +
  VPNv4/v6 only. EVPN (MAC routes don't hash by IP prefix, ESI
  cross-deps), flowspec, SR-Policy, BGP-LS, RTC stay main-owned —
  they are small tables; sharding them buys nothing and complicates
  the partition.
- **D4 — Default shard count (C.4)**: recommend shipping default 1
  (sharding opt-in) until our own perf matrix justifies a derived
  default (e.g. `min(4, cores/2)`).

## 9. Performance record

Harness: `tools/bgp-bench` (Phase 0.1, PR #1406). Methodology: N eBGP
senders blast the same `--prefixes` set (RIB-FIB ratio = N), 2 eBGP
receivers count re-advertisements; convergence = blast start → last
announce at the slowest receiver (3s quiet window, excluded from the
number). Daemon config: `no-fib-install true`, MRAI 1s both peer
types (±1s quantization floor).

Machine: the early baseline table below is a 5-vCPU VM (model not
exposed), 31 GB RAM, Linux 6.8.0-124-generic; the 12-core matrices
(Implementation status §"Measured" and the base-vs-sharded sweep below)
are a later 12-core / 31 GB box. Flamegraph pending: `perf_event_paranoid=4`
blocks unprivileged perf on these boxes and user namespaces are
restricted — thread-level attribution needs a root run (recipe in the
bench README). The single-task serialization claim in §3 is now
corroborated by the workload profiles in "Implementation status":
`PrefixTrie::walk_enclosing` 74.8 % (policy-heavy), SipHash interning
~28 %, and the allocator's `osq_lock` ~12 % at N=12 — all single-core
hotspots that the policy-parallelism, sharding, and allocator/hasher
swaps target.

Baseline, branch point `41a1d07d` (2026-06-12):

| senders × prefixes | paths in | convergence | unique pfx/s | paths/s in | daemon RSS |
|---|---|---|---|---|---|
| 4 × 100k | 400k | 1.564s | 64.0k | ~256k | 789 MB |
| 8 × 100k | 800k | 4.556s | 21.9k | ~176k | 1.43 GB |
| 4 × 500k | 2.0M | 8.147s | 61.4k | ~245k | 3.69 GB |

Observations: per-path throughput *drops* as candidates-per-prefix
rise (8-sender row), and the 4×500k run re-advertised 1.17M NLRIs for
500k prefixes — best-path flips between senders' paths during ingest
roughly double the egress work. Both are exactly the costs that shard
(per-prefix re-election) and update-worker (egress encode) parallelism
attack.

Per-step results (same matrix) land here as A.2 / B.5 / C.4 complete.
Re-running the matrix on the unchanged baseline binary showed ~10%
run-to-run variance (announce counts vary 2× with best-path-flip
timing), so single-run deltas below that are noise.

| Step | 4×100k | 8×100k | 4×500k |
|---|---|---|---|
| Baseline | 1.564s | 4.556s | 8.147s |
| A.2 (PR #1416, 2 runs) | 1.64–1.76s | 4.65–4.70s | 7.55s |
| B.3 sync-dispatch (N=1) | parity ±noise | parity ±noise | parity ±noise |
| C.4 (best) | | | |

A.2 reading: parity within noise at the 100k scales, ~7% at 2M paths.
Expected — A.2 offloads the per-group encode, whose cost scales with
member fan-out, and this matrix has only 2 receivers. The structural
win is the freed main loop; C.2 (update-workers) is where egress
parallelism actually pays.

**B.3 sync-dispatch (N=1) reading**: this *no-policy* matrix is the
wrong workload to show the built C.1/C.2 — its per-route work is intern
+ best-path + encode, not policy, so routing through `BgpShard::handle`
is parity-within-noise (the dispatch is the same core, the win was never
here). The built policy-parallelism C.1/C.2 are measured on the
policy-heavy workload in the "Implementation status" section above
(serial 19.57s → 4.34s at 12 cores). The planned multi-shard C.1 /
update-worker C.2 are what this matrix is meant to capture, when built.

**Base-vs-sharded sweep (12-core, 8×500k no-policy) — 2026-06-14, HEAD
`3a27ec65`.** Fresh back-to-back run on the 12-core box (12 cores, 31 GB,
Linux 6.8.0-124-generic): base rebuilt from the pre-sharding branch point
`41a1d07d` and driven by the *same* `bgp-bench` binary, then
`ZEBRA_BGP_SHARDS` swept on the current build (one binary, daemon restart
per run, 3 runs each). Harness as above — 8 senders, 2 receivers, 500k
prefixes, `no-fib-install`, MRAI 1s.

| build | r1 | r2 | r3 | avg | vs base |
|---|---|---|---|---|---|
| base (pre-sharding `41a1d07d`) | 22.29 | 22.51 | 23.31 | 22.70 s | — |
| N=1 (sync-dispatch) | 17.28 | 16.37 | 17.42 | 17.02 s | −25 % |
| N=4 | 14.29 | 14.88 | 14.09 | 14.42 s | **−37 % (knee)** |
| N=12 | 16.56 | 15.18 | 17.85 | 16.53 s | −27 % |

Daemon RSS 7.0 GB (base) → 7.6 GB (N=12); all 12 runs converged. This
reproduces the earlier 12-core matrix (Implementation status,
§"Measured"): N=4 absolute matches to ~0.1 s (14.42 vs 14.44), N=12 to
~0.1 s (16.53 vs 16.61); base ran ~2 s slower this session (22.70 vs the
earlier 20.73, inside the ~10 % run-to-run variance), so the relative
deltas come out slightly larger. Two takeaways hold. **(1) N=1 is already
−25 % with no parallelism** — sync-dispatch is the same single ingest
thread as base, so the win is the branch's global swaps (mimalloc
allocator + `ahash` attr-interning hasher in `store.rs`, both absent at
base), not sharding. **(2) the shard fan-out adds ~12 points** (N=1 −25 %
→ N=4 −37 %), then over-shards at N=12 (no spare cores for the reduce +
tokio I/O). The AddPath fix `3a27ec65` is benchmark-neutral here (IPv4
load; it touches only the v6/LU advertise loops).

## 10. Caveats & out of scope

- **Gains require scale and fan-out** (high RIB-FIB ratio, many
  peers). A 2-peer BDD topology shows zero or negative gain — that is
  expected, BDD is the correctness gate, the §9 matrix is the perf
  gate.
- **Phase C was gated on the Phase 0 profile — and the profile bore it
  out.** Interning (SipHash ~28 %) and allocation (`osq_lock` ~12 %) did
  dominate, so both were fixed single-threaded first (ahash + mimalloc,
  which alone get N=1 to −25 % vs base) before the shard fan-out — exactly
  the "fix that first" the plan called for.
- **The next bottleneck moves to the central RIB daemon** (single
  task) for 1:1 RIB-FIB roles — out of scope here, bounds end-to-end
  gains for non-RR roles.
- Out of scope: live resharding on knob change, sharding inside
  per-VRF tasks (they stay single-shard; the machinery is reusable
  later), reader-direct shard dispatch (requires epochs, §7), RIB
  daemon parallelism, EVPN/flowspec/SR-Policy/BGP-LS sharding.

## 11. Prior art: parallelism in BIRD 3.x and GoBGP

Extracted to its own memo:
[`bgp-sharding-prior-art.md`](bgp-sharding-prior-art.md). BIRD 3.3.0
(branch `stable-v3.3`) and GoBGP (`master`) were both read in full to
place zebra-rs's design — the sharp question being **how each
parallelizes a single BGP table's work** (best-path and advertise).
Three different answers:

- **BIRD 3.3** parallelizes *across* tables/protocols, never within one
  table: a single table's best-path is **serial** under one per-table
  lock, reads are lock-free (RCU caches), and egress is **parallel per
  consumer** via lock-free journals (`lfjour`).
- **GoBGP** shards one table by prefix hash across **2048 bucket *locks***
  over shared memory; best-path runs in parallel across prefixes but
  inside the lock, and export *policy* runs serially on the producer
  (only encode/write is per-peer parallel).
- **zebra-rs** shards by prefix hash into **owned** shards
  (shared-nothing, no hot-path locks). Both BIRD and GoBGP parallelizing
  egress per-peer is the cross-validation for Phase E.

The memo carries the full architecture of each, diagrams, the comparison
table, verified source anchors, and the per-stack takeaways (incl.
corrections to the framing summarized here).

## 12. Improvement roadmap (prior-art-informed)

The §11 comparison places zebra-rs as the only shared-nothing design of
the three — which fits Rust (ownership > GC'd shared pointers > lock-free
RCU) and gives the strongest compute-parallel and egress-parallel story.
Three architectural gaps remain, in priority order. The first two are the
two places all three stacks differ; the third is where zebra is uniquely
constrained.

**P1 — E.2+ group-affinity update-workers, fed by a per-shard journal.**
Today the shard reduce parallelizes the *out-policy precompute* (E.1/E.2)
but the bucketing / cache / encode / adj-out still run **serially on the
main reduce thread**. The full Juniper form moves per-group egress into M
dedicated workers with static group→worker affinity, fed `AdvDelta` (RTO)
directly by the shards, bypassing the main reduce. BIRD 3.x is the
reference substrate: a **per-shard append-only journal** (the `lfjour`
shape — seq numbers + a per-worker cursor) lets each update-worker *pull*
deltas at its own pace instead of main fanning them out. The Adj-RIB-Out
unification (above) is the enabler — every family now has the per-peer
`adj_out` a worker diffs against. Ordering still holds: one prefix → one
shard → one worker. This is the single highest-value remaining item and
the one §11 explicitly points at.

**P2 — Backpressure.** Every inter-thread channel is currently unbounded
(shard inbox `std::sync::mpsc`, the tokio result channel, the egress
hand-off) — the same soft spot GoBGP has (`InfiniteChannel`), and the one
place BIRD is clearly ahead (the `lfjour` token + slowest-consumer
watermark GC bounds the journal). A slow consumer (peer, FIB, RIB daemon)
can grow memory unboundedly. Options: bounded channels with `try_send` +
overflow accounting, or — if P1 lands a journal — adopt BIRD's
watermark/token model directly on it (GC to the slowest cursor). Decide
after a fan-out/slow-peer bench, not before.

**P3 — Decouple ownership granularity from worker-thread count.** Today
`shard == OS thread`, so the shard count is simultaneously the ownership
granularity *and* the parallelism degree — which is exactly why the knee
is N=4 (not N=cores) and why shards fight the egress pool for cores (the
`max(1, cores − shards)` split). Both other stacks separate these: GoBGP
has 2048 lock/ownership domains served by `GOMAXPROCS` goroutines; BIRD
3.x's `birdloop` balancer work-steals many loops onto a fixed thread
pool. The analogue here: many *logical* shards (fine, stable prefix
ownership) mapped onto a small fixed worker pool by work-stealing, so the
operator stops hand-tuning N against core count. Larger refactor; only
worth it if the N-tuning friction proves real on production workloads.

**Lower priority / already noted.** Extending pooled dispatch to
v6/VPNv6/LU (immediate gap above) is mechanical, not architectural. The
central RIB daemon becoming the next serial bottleneck for 1:1 RIB-FIB
roles (§10) bounds end-to-end gains regardless of BGP-side sharding — a
separate effort.
