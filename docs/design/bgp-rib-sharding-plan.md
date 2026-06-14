# BGP RIB Sharding (Juniper-style)

Status: **Phase 0 + A merged; Phase B built at N=1 (sync-dispatch);
policy-parallelism C.1/C.2 built; N-shard dedicated-thread pool +
RouteBatch + mimalloc built (dark behind `SHARDS=1`); Phase E.1
(parallel advertise-outcome precompute) built** — Phase 0 + A merged
2026-06-12
(PRs #1402/#1406/#1408/#1416). Phase B (state partition, message
protocol, shard) and a re-scoped Phase C (parallel policy evaluation)
were built 2026-06-13 on a WIP branch. Two deliberate divergences from
the §5–8 plan: **B.3 became a synchronous dispatch, not a spawned task**,
and **Phase C was re-scoped to parallelize the pure policy walk (rayon)
rather than fan out to N shards** (the multi-shard form remains future).
The "Implementation status" section below is the current architecture of
record; §1–10 remain the original applicability analysis and design
rationale. Open decisions §8: D1 (in-repo `bgp-bench`) and D3
(v4/v6-unicast+LU+VPN scope) resolved as recommended; D2 (channel
boundedness) moot under sync dispatch — there is no data channel yet;
D4 (default shard count) deferred — the N-shard path now exists but
ships dark behind the `SHARDS` constant (default 1).

Source: "BGP RIB Sharding" — Ravindran Thangarajah, Juniper Networks,
2022-10-24.
<https://community.juniper.net/blogs/ravindran-thangarajah/2022/10/24/bgp-rib-sharding>

## Implementation status (as built — 2026-06-13)

What actually shipped diverges from the §5–8 plan in two deliberate
ways: B.3 became a **synchronous dispatch** rather than a spawned task,
and Phase C was **re-scoped** to parallelize the pure policy walk (rayon)
instead of (yet) fanning out to N shards. §5–10 remain the original
design rationale.

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
  - **Dispatch vs direct access**: v4-unicast + VPNv4 reach the shard via
    `UpdateV4`, v6-unicast + VPNv6 via `UpdateV6`. **Labeled-unicast
    (v4/v6) still uses direct shard-table access** (`route_labelv4_update`
    → `bgp.shard.update_v4lu`); the `UpdateLu` + `WithdrawV4/V6/Lu`
    variants are wired-but-unused scaffolding for a later migration (the
    dead-code warnings on them are expected).

### Phase C — re-scoped to parallel policy evaluation (C.1/C.2, built)

The planned C.1 (N-shard fan-out) and C.2 (update-workers) are **not yet
built — the shard is still single (N=1)**. Instead, profiling the N=1
build under a realistic policy-heavy workload (a 1000-entry route-map
applied inbound *and* outbound) put **74.8 % of CPU in
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

### Phase N-shard — dedicated-thread pool (as built, dark behind `SHARDS=1`)

The planned multi-shard fan-out (original C.1) is now built, but on
**dedicated OS threads, not tokio tasks or rayon** — the rayon-per-UPDATE
form (the re-scoped C.1/C.2 above) regressed the no-policy workload ~36 %
(a `par_iter` tax with no policy to amortize), so the shard became a real
thread that owns its slice end-to-end.

- **`ShardPool`** (`bgp/shard/pool.rs`) spawns `SHARDS` worker threads
  (`std::thread`), one per `BgpShard`. A worker blocks on an `mpsc`
  inbox, runs `BgpShard::handle(msg, None)`, and ships a `ShardResult`
  back over a tokio `UnboundedSender`. CPU-bound work on real threads
  keeps it off the tokio runtime and away from the I/O (reader/writer)
  tasks.
- **`shard_of(addr)`** = FNV-1a over the address octets `% N`
  (deterministic, address-only) so unicast / LU / VPN rows of one prefix
  co-locate (the Juniper invariant) with no cross-shard synchronization.
- **Gated on `SHARDS > 1`** (`inst.rs`): at the default `SHARDS == 1`
  nothing spawns, the synchronous `shard` field + byte-identical sync
  path run, and the event loop's `shard_results_rx` arm stays idle — so
  BDD and every default run traverse the proven N=1 path.
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

**Measured (12-core, no-policy 8×500k, interleaved A/B).** Pre-sharding
baseline ~20.5 s. Isolation showed the shard *dispatch* is free
(sync-dispatch ≈ baseline) and ahash interning even helps (−11 %), but
naive sharding regressed the workload anyway: the ungated rayon policy
par_iters (+46 % — they fork-join with no policy to amortize), the
per-prefix dispatch storm (+26 % at N=12), and allocator contention.
RouteBatch + mimalloc + **uniform cost-gating of every rayon par_iter**
(C.1 inbound, C.2 outbound, E.1 reduce — each fans out only when its policy
is bound) fixed all of it: **default N=1 16.5 s (−19 %), N=12 15.7 s
(−23 %)** — both now beat the serial baseline, the once-+20 % default
config the bigger turnaround. On this no-policy load the wins are mostly
ahash + mimalloc + de-taxing the par_iters; the shard parallelism itself
adds only the last ~5 % (N=1 16.5 s → N=12 15.7 s). It pays far more under
policy (C.1/C.2 above; E.1 −39 % at N=12) or high RIB-FIB fan-out (§9).

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
- **E.2+ (future) — dedicated update-worker threads.** Move the per-group
  caches + adj-out + encode into M worker threads with static
  group→worker affinity, fed `AdvDelta` (RTO) directly by the shards
  (bypassing the main reduce). BIRD 3.x (a per-protocol loop pulls a
  lockfree journal, then filters + encodes on its own thread) and GoBGP
  (a per-peer send goroutine) are the two reference designs (§11).
  Per-(peer, prefix) ordering holds: one prefix → one shard → one worker.

### Still future

N>1 barriers (planned C.3: EoR / refresh / GR-LLGR sweeps
broadcast-and-ack), N>1 show / clear / sync scatter-gather (B.4 is still
inline — at N>1 they read the empty main shard), `PolicyReplace`
(per-peer policy snapshots replicated to shards — Phase C uses
default-permit, correct only for no-configured-policy), the YANG knob
`router bgp shards <1-64>` to replace the `SHARDS` constant, and the perf
matrix + shipping default (planned C.4).

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
| Shard thread owning a RIB slice | tokio shard task owning a `LocalRibTable<P>` partition + adj-in slices | to build — but the per-VRF task (`process_vrf_global_msg`) is this exact pattern, sharded by table instead of by hash |
| RTO (prefix + attr shorthand) | `(Arc<BgpAttr>, Nlri, source_ident)` — the *existing* update-group cache entry (`bgp/update_group.rs:181`) | exists — zebra-rs invented the RTO without naming it |
| Update thread packing RTOs | update-worker task owning `UpdateGroup` caches + debounce timers + canonical encode | encode logic exists (update-groups Phase 3, shipped for IPv4); needs to move off the main task |
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
dark behind `shards = 1` until C.4. Status column to be filled in as
PRs land.

| Step | Title | Depends on | Status |
|---|---|---|---|
| 0.1 | Bench harness + baseline profile | — | merged (PR #1406) |
| A.1 | Flush job extraction (pure function) | — | merged (PR #1408) |
| A.2 | Flush offload to worker | A.1 | merged (PR #1416) |
| B.1 | State partition: `BgpShard` struct, adj-in re-keying | — | ✅ built (WIP branch) |
| B.2 | Shard message protocol + label sub-blocks | B.1 | ✅ built (WIP branch) |
| B.3 | ~~Spawn shard task~~ → **sync dispatch** at N=1 | B.2 | ✅ built — pivoted to sync, see "Implementation status" |
| B.4 | Show / clear / sync scatter-gather | B.3 | 🔶 partial — `Show` wired; clear/sync still inline |
| B.5 | BDD + lifecycle hardening at N=1 | B.4 | ⏳ |
| C.1 | Prefix-hash fan-out to N shards + YANG knob | B.5 | ⏳ deferred (label reused — see note) |
| C.2 | Update-worker tasks (group affinity) | A.2, C.1 | ⏳ deferred (label reused — see note) |
| C.3 | Barriers: EoR, refresh, GR/LLGR sweeps, clear | C.1 | ⏳ |
| C.4 | Perf matrix, defaults, docs | C.2, C.3 | ⏳ |

> **Phase C label note**: the *built* "C.1/C.2" are a re-scope —
> rayon-parallel inbound/outbound **policy** evaluation at N=1 (see
> "Implementation status"). The rows above are the *original* plan's
> C.1/C.2 (multi-shard fan-out + update-workers), which remain deferred.
> Same letters, different axis of parallelism.

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

## 8. Open decisions (need a ruling before the affected step)

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

Machine: 5-vCPU VM (model not exposed), 31 GB RAM, Linux
6.8.0-124-generic. Flamegraph pending: `perf_event_paranoid=4` blocks
unprivileged perf on this box and user namespaces are restricted —
thread-level attribution needs a root run (recipe in the bench
README). The single-task serialization claim in §3 rests on code
structure, not yet on a profile.

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

## 10. Caveats & out of scope

- **Gains require scale and fan-out** (high RIB-FIB ratio, many
  peers). A 2-peer BDD topology shows zero or negative gain — that is
  expected, BDD is the correctness gate, the §9 matrix is the perf
  gate.
- **Phase C is gated on the Phase 0 profile.** If the flamegraph shows
  allocations/interning dominate, fix that single-threaded first.
- **The next bottleneck moves to the central RIB daemon** (single
  task) for 1:1 RIB-FIB roles — out of scope here, bounds end-to-end
  gains for non-RR roles.
- Out of scope: live resharding on knob change, sharding inside
  per-VRF tasks (they stay single-shard; the machinery is reusable
  later), reader-direct shard dispatch (requires epochs, §7), RIB
  daemon parallelism, EVPN/flowspec/SR-Policy/BGP-LS sharding.

## 11. Prior art: parallelism in BIRD 3.x and GoBGP

Two other open BGP stacks were read in full — BIRD 3.3.0 (branch
`stable-v3.3`) and GoBGP (`master`) — to place zebra-rs's design. The
sharp question is **how each parallelizes a single BGP table's work**
(best-path and advertise). Three different answers.

### BIRD 3.3 — per-protocol / per-table loops, serial within a table

BIRD 3 is a ground-up multi-threaded redesign (2.x was a single event
loop). A configurable **thread pool** (`bird_thread_start` →
`pthread_create`, `sysdep/unix/io-loop.c:1253`) runs **`birdloop`s**; a
work-stealing balancer (`birdloop_balancer`, io-loop.c:832) picks up and
migrates loops between threads. The unit of concurrency is the **loop**:
each protocol instance gets one (`nest/proto.c:1568`) and **each routing
table gets its own service loop** (`nest/rt-table.c:3808`).

- **A single table is serialized.** All imports + best-path
  (`rte_recalculate`) for one table run on that one loop under `RT_LOCKED`
  (rt-table.c:2765). There is **no per-prefix sharding within a table** —
  BIRD parallelizes *across* tables and protocols.
- **What it makes lockless instead — the reads.** Export is a **lockfree
  journal** (`lfjour`, rt-table.c:3856): the table loop writes deltas,
  each protocol loop *pulls* them locklessly and runs its export filter +
  encode **on its own loop** → egress is parallel per peer. The attribute
  cache (RCU hash, `nest/rt-attr.c`) and the netindex prefix interning
  (`lib/netindex.c`) are RCU/lockless so lookups never take the table
  lock. A strict lock-domain order (`lib/locking.h`:
  `the_bird < … < service < rtable < attrs`) prevents deadlock when a
  protocol loop crosses into a table loop.

### GoBGP — per-peer goroutines + prefix-hash *lock* sharding

GoBGP recently retrofitted prefix-hash sharding — convergent with our
design, but via locks over shared memory. Per peer there is an FSM
goroutine plus recv + send goroutines (`pkg/server/fsm.go`); a central
`Serve()` loop handles mostly management. `propagateUpdate`
(`pkg/server/server.go:1222`) hashes each path to **one of 2048 bucket
mutexes** — `farm.Hash64(family+prefix) % 2048` (server.go:112,131) —
with a nested per-destination shard lock (`internal/pkg/table/table.go`).
Best-path (`Destination.Calculate`) and import policy run on the **per-peer
recv goroutine**, parallel across prefixes but *inside* the bucket lock.
Egress encode is **parallel per-peer** (each send goroutine encodes its
own UPDATEs).

### zebra-rs — prefix-hash *ownership* sharding (shared-nothing)

N dedicated threads each **own** a prefix-hash slice of the Loc-RIB — no
shared table, **no locks** on the hot path; main↔shard is message
passing. Best-path + inbound policy run inside the owning shard; advertise
runs on the main reduce (Phase E.1 parallelizes its out-policy; E.2 will
move it to update-worker threads).

### The picture

| | BIRD 3.3 | GoBGP | zebra-rs |
|---|---|---|---|
| Concurrency unit | loop (per-proto, per-table) | per-peer goroutine + 2048 lock-buckets | per-prefix-hash **owned** shard thread |
| Single table's best-path | **serial** (one table loop) | parallel (bucket mutexes) | parallel (owned shards) |
| RIB memory model | shared, RCU reads + domain locks | shared, 2048 bucket mutexes | **partitioned, shared-nothing** |
| Hot-path lock cost | RCU reads lock-free; table write serial | mutex + cache-coherency per update | **none** (message passing) |
| Egress / advertise | **parallel per-peer** (lockfree journal) | **parallel per-peer** (send goroutine) | serial reduce → E.1 parallel out-policy → E.2 workers |

**Takeaways.** (1) Two mature stacks independently shard the RIB by prefix
hash — strong validation of the direction; ours is the shared-nothing
variant (no lock / coherency tax), which is why RouteBatch + mimalloc put
convergence *below* the serial baseline — a lock-based design rarely beats
its own baseline. (2) Both BIRD 3 and GoBGP parallelize **egress per-peer**;
we don't yet — that is Phase E, now validated from two directions. (3)
BIRD 3's RCU attribute cache / netindex is the reference for our
cross-shard interning question: at large N, either duplicate the intern
table per shard (memory) or share one behind RCU/lockfree (BIRD's choice).
