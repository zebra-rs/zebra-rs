# TI-LFA Parallel SPF Computation — Design (IS-IS first)

Status: COMPLETE (2026-06-12) for both protocols. Shipped: IS-IS
#1384 (spf refactor + oracle tests), #1390 (modes + wiring + config +
telemetry), #1395 (BDD + `tilfa_perf_modes` harness); OSPF #1399
(v2+v3 port per §13), #1400 (BDD). Remaining potential work is
tracked in `tilfa-parallel-spf-followups.md` (supersedes §14 here).
Operator documentation: `book/src/ch-12-00-nexthop-protect.md`.
Decisions: rayon substrate; default mode `serial`; **no redundant SPF
in any mode** — serial is the sequential 2-SPF-per-target loop, not the
legacy 3-SPF path (see §6.0, §15).

## 1. Problem

TI-LFA dominates SPF-cycle CPU. After the primary reachability SPF, the
current code computes, **per protected destination `d`**, three more
SPFs (see `spf::tilfa`, `zebra-rs/src/spf/calc.rs:529`):

| step | call | SPF |
|---|---|---|
| P-space | `p_space_vertices(graph, s, x)` | forward SPF from `s`, **unmodified graph**, filter by `x` |
| Q-space | `q_space_vertices(graph, d, x)` | reverse SPF from `d`, **unmodified graph**, filter by `x` |
| PC-path | `pc_paths(graph, s, d, x)` | forward SPF from `s` with `x` **excluded**, extract `d` |
| repair | `intersect` + `make_repair_list` | none (cheap walk) |

Total per run: `1 + 3·N` SPFs for `N` protected destinations, all run
**serially on one thread** — the single `tokio::task::spawn_blocking`
worker dispatched by the `Message::SpfCalc` handler
(`zebra-rs/src/isis/inst.rs:1755`). A 1 000-router level means ~3 000
serial Dijkstras per SPF cycle while the other cores idle.

Goal: use multi-core CPU for the TI-LFA bulk, with the degree and shape
of parallelism **operator-configurable** in three modes (Aggressive /
Conservative / Sharding). IS-IS first; OSPF (v2+v3) reuses the shared
machinery later.

## 2. Current pipeline (unchanged by this design)

```
Message::SpfCalc(level)                         inst.rs:1717
  ├─ spf_inflight latch / spf_pending coalesce  inst.rs:1738
  ├─ build_spf_input(top, level)                rib.rs:1157   (main task: graph build, owned snapshot)
  └─ tokio::task::spawn_blocking                inst.rs:1755
        └─ compute_spf(SpfInput) -> SpfOutput   rib.rs:1225   (worker: Dijkstra + TI-LFA + MT2 + flex-algo)
Message::SpfDone(SpfOutput)                     inst.rs:1760
  └─ apply_spf_result(top, output)              rib.rs:1313   (main task: RIB build + diff + publish)
```

Everything in this design happens **inside `compute_spf`**, which
already runs on a blocking thread and owns its inputs (`SpfInput`
carries the graph, the lsp_map snapshot, sources — no borrows on
`IsisTop`). The message flow, the per-level inflight/pending latch, and
`apply_spf_result` are untouched.

## 3. Two algebraic identities (work elimination before parallelism)

Reading `spf/calc.rs` yields two exact identities that shrink the work
pool before any thread is spawned. Both are pure-function memoization —
results are bit-identical.

**(I1) The P-space SPF is the primary SPF.**
`p_space_vertices` (calc.rs:323) internally runs
`spf(graph, s, SpfOpt::full_path())` — the *same graph, same root, same
options* as the primary SPF already computed at rib.rs:1244 (and
mt2 at rib.rs:1259). `x` only affects the *filter* applied afterwards.
So P-space needs **zero additional SPF**: filter the existing
`spf_result` per distinct `x`. This removes `N` SPFs even in
single-threaded operation.

**(I2) The PC-path SPF depends on `x`, not `d`.**
`pc_paths` (calc.rs:351) runs `spf_calc(graph, s, x, full_path, Normal)`
and then merely extracts `d`'s entry. Destinations sharing the same
protected first-hop `x` share the identical modified-graph SPF tree.
Distinct `x` values are bounded by the number of first-hop neighbors
(`|X| ≪ N`). So the `N` PC SPFs dedup to `|X|`.

The Q-space reverse SPF is rooted at `d` (calc.rs:337) — genuinely
per-destination and the irreducible bulk: `N` reverse SPFs.
(Its `x` is also filter-only, which future multi-failure/SRLG work can
exploit, but with one `x` per `d` today there is nothing to share.)

Resulting cost model (primary SPF excluded, common to all):

| | SPFs per run |
|---|---|
| today (serial) | `3·N` |
| after I1 | `2·N` |
| after I1 + I2 | `N + |X|` |

Example, 1 000 routers / 8 neighbors: 2 997 → 1 007 SPFs (~3× less
CPU), and those 1 007 then spread across cores. On 16 cores the TI-LFA
wall-clock is ~63 SPF-times vs ~3 000 today — roughly **45×**.

## 4. Work model

A *target* is what the per-destination loop in
`isis/tilfa.rs:468 tilfa_repair_path` derives today (skip source, skip
SPF-level ECMP, skip pseudonodes, advance `x` past a leading LAN
pseudonode):

```rust
pub struct TilfaTarget { pub d: usize, pub x: usize }
```

Per target, the work decomposes into jobs:

- `P(x)`  — filter of `spf_result` (no SPF; O(paths) scan) — shared per `x` (I1)
- `PC(x)` — one modified-graph SPF — shared per `x` (I2)
- `Q(d)`  — one reverse SPF + filter — per target
- `reduce(d)` — `intersect` + `make_repair_list` + first-hop extraction
  from `PC(x)`'s tree — cheap, no SPF

## 5. Execution substrate

**Decision: rayon** (new workspace dependency, `rayon = "1"`), used
*inside* `compute_spf`:

- The global rayon pool (lazily built, `available_parallelism` threads)
  gives a **process-wide hard ceiling**: L1 + L2 runs, VRF instances,
  and later OSPF all share it, so concurrent SPF cycles cannot
  oversubscribe the box no matter how many instances fan out at once.
- `par_iter` borrows `&Graph` / `&spf_result` directly (everything in
  `SpfInput` is owned and `Sync`) — no `Arc`, no clones, no `'static`.
- Work-stealing absorbs the high variance between individual SPF costs.
- Pool threads are born lazily on first `par_iter` — zero cost while
  every instance runs `serial`.

Alternatives considered:

- `tokio::task::spawn_blocking` per job — **rejected**: the blocking
  pool is sized for I/O (512 threads), so 1 000 CPU-bound jobs would
  heavily oversubscribe; `'static` closures force `Arc` snapshots; jobs
  would compete with genuine blocking I/O users of the pool.
- Hand-rolled `std::thread::scope` + atomic work index — viable
  (~40 lines, no new dependency) and kept as the fallback if we decide
  against rayon. Downsides: thread spawn per SPF cycle, and no shared
  global ceiling across concurrently-running instances (L1+L2+VRFs each
  spawn their own width-`W` sets).

`compute_spf` blocks its `spawn_blocking` thread until the fan-out
finishes — exactly as it blocks today while computing serially. No
nested `par_iter` is used, so there is no rayon-deadlock surface.

## 6. The modes

Per the locked decisions, **no mode performs a redundant SPF**: the
P-space SPF (pure waste by I1) is gone everywhere, replaced by the
shared per-`x` filters. The legacy 3-SPF path survives only as
`spf::tilfa` — the self-contained single-destination reference used as
the equivalence-test oracle and by OSPF until its conversion (§13).

All modes return the same `BTreeMap<usize, Vec<RepairPath>>`
(equivalence guaranteed — §9).

### 6.0 Serial (default) — sequential, no fan-out

The per-target computation run as a plain loop on the `compute_spf`
thread:

```text
precompute  p_sets[x] = P(x) for each distinct x        (filters, cheap)
for each target t:
    q  = q_space_vertices(graph, t.d, [t.x])            ← SPF 1
    pc = spf_calc(graph, s, [t.x], full_path, Normal)   ← SPF 2
    emit (t.d, repair_from_parts(graph, s, p_sets[t.x], q, pc[t.d]))
```

`2·N` SPFs, one thread, rayon never engaged (the global pool is not
even spun up on a default config). Identical results to today at ~⅔ the
CPU. The switch from the legacy 3-SPF loop happens when IS-IS moves to
`tilfa_compute` (PR-B); PR-A itself changes no behavior.

### 6.1 Conservative — task per destination

The serial loop's body executed with `par_iter` — same closure, no
shared SPF work between tasks:

```text
precompute  p_sets[x]                                    (as in serial)
par over targets t:  same body as serial                 (2 SPFs per task; PC recomputed per target — the simplicity tradeoff)
```

`2·N` SPFs; concurrency `min(N, pool)`; tasks share only read-only
inputs. Peak transient memory: `width × (1 PC tree + 1 Q set)`.

### 6.2 Aggressive — map-reduce at SPF granularity

Two phases; the reduce is fused into the Q job so no global barrier
holds `N` intermediate results:

```text
phase A  par over distinct x:  pc_trees[x] = PC(x)      (|X| SPFs)
         p_sets[x] precomputed as in conservative
phase B  par over targets t:
             q = Q(t.d)                                  (N SPFs)
             emit (t.d, repair_from_parts(…, pc_trees[t.x].get(t.d)))
```

`N + |X|` SPFs — full dedup; concurrency `min(N, pool)`; fastest
wall-clock and lowest total CPU. Peak memory: `|X|` PC trees live for
the whole run + `width` transient Q sets.

### 6.3 Sharding(K) — operator-bounded static task count

Targets are grouped by `x` (groups are dedup units), then groups are
LPT-bin-packed by target count into ≤ `K` shards:

```text
par over shards (≤ K concurrent):
    for (x, targets_of_x) in shard:        # groups processed contiguously
        p  = p_sets[x];  pc = PC(x)        # once per group
        for t in targets_of_x:  q = Q(t.d); emit reduce(t)
        # pc dropped at group end → ≤1 live PC tree per shard
```

Same `N + |X|` SPF count as aggressive (each `x`-group lands wholly in
one shard), but at most `K` SPFs run concurrently — the operator's hard
upper bound on TI-LFA parallelism, e.g. to reserve cores for BGP/BFD on
a shared box. `K = 1` ≈ serial-with-dedup (useful baseline). Memory:
`≤ K × (1 PC tree + 1 Q set)`.

### 6.4 Summary

| mode | SPFs | max concurrent SPFs | shared state | peak extra memory |
|---|---|---|---|---|
| serial (default) | `2N` | 1 | read-only P-sets | 1 tree + 1 set (transient) |
| conservative | `2N` | `min(N, pool)` | read-only P-sets | `W·(tree+set)` |
| aggressive | `N+|X|` | `min(N, pool)` | P-sets + `|X|` PC trees | `|X|` trees + `W` sets |
| sharding(K) | `N+|X|` | `min(K, pool)` | per-shard PC memo | `K·(tree+set)` |

`sharding(1)` is the lowest-CPU single-threaded configuration
(`N+|X|` SPFs, full dedup, no concurrency).

`pool` = rayon global pool width (≈ cores), `W = min(N, pool)`.

## 7. Code layout

### 7.1 `src/spf` (protocol-neutral; OSPF reuses)

- `spf/calc.rs` — extract the post-SPF tail of `spf::tilfa`
  (calc.rs:534-579: ECMP loop, first-hop-link extraction, `intersect`,
  `make_repair_list`) into
  `repair_from_parts(graph, s, p, q, pc_paths: &[Vec<usize>],
  first_hop_links: &HashSet<(usize, u32)>) -> Vec<RepairPath>`
  (slice/set parameters rather than `&Path` so both `pc_paths()`'s
  cloned output and a borrowed tree entry feed it); add
  `p_space_from_spf(spf_result, s, x) -> BTreeSet<usize>` (the filter
  body of `p_space_vertices`, which is reimplemented on top).
  `spf::tilfa` is reimplemented on top of both — its public signature
  and behavior are unchanged (existing unit tests pin this). Derive
  `PartialEq/Eq` on `RepairPath` + `SrSegment` for equivalence tests.
- `spf/tilfa_par.rs` (new) —
  ```rust
  pub enum TilfaComputeMode { Serial, Conservative, Aggressive, Sharding(u16) }  // Default = Serial
  pub struct TilfaTarget { pub d: usize, pub x: usize }
  pub struct TilfaStats { mode, targets, q_spf, pc_spf, pc_deduped, width, duration }

  pub fn tilfa_compute(
      graph: &Graph, source: usize,
      spf_result: &BTreeMap<usize, Path>,
      targets: &[TilfaTarget],
      mode: TilfaComputeMode,
  ) -> (BTreeMap<usize, Vec<RepairPath>>, TilfaStats)
  ```
  Serial arm is the conservative closure run on a plain iterator (§6.0)
  — rayon stays untouched on default configs. Group/bin-pack helpers
  (`group_by_x`, `lpt_binpack`) live here with unit tests.

### 7.2 `src/isis`

- `isis/tilfa.rs` — `tilfa_repair_path` splits into
  `tilfa_targets(graph, lsp_map, source, spf_result) -> Vec<TilfaTarget>`
  (the existing skip/X-derivation logic at tilfa.rs:476-512, verbatim)
  plus a call to `spf::tilfa_compute(…, mode)`.
- `isis/rib.rs` — `SpfInput` gains `tilfa_mode: TilfaComputeMode`
  (snapshotted from config in `build_spf_input`); `compute_spf` passes
  it to both the legacy and MT2 TI-LFA calls; `SpfOutput` gains
  `tilfa_stats: Option<TilfaStats>`; `apply_spf_result` stashes it on
  `IsisTop` next to `spf_duration`.
- `isis/inst.rs` — no changes (mode rides `SpfInput`).
- Flex-algo: no TI-LFA today → unaffected.
- VRF instances: forward-to-full-instance config means each VRF gets
  the knob for free; all instances share the global rayon pool, so the
  aggregate ceiling stays ≈ core count.

## 8. Configuration

YANG (`zebra-rs/yang/config.yang`, inside the existing
`/router/isis/fast-reroute/ti-lfa` presence container, config.yang:1505):

```yang
container ti-lfa {
  presence "Enable Topology-Independent LFA (TI-LFA)";
  container compute-mode {
    // One keyword per mode under a `choice`; the shard count nests
    // under `sharding`, the only mode it applies to. Mutually
    // exclusive cases; the default mode (serial) is applied by the
    // handler (a choice/case carries no YANG default).
    choice mode {
      case serial       { leaf serial       { type empty; } }  // current behavior (default)
      case conservative { leaf conservative { type empty; } }  // task per destination
      case aggressive   { leaf aggressive   { type empty; } }  // SPF-granularity map-reduce, full dedup
      case sharding {
        container sharding {
          presence "Shard the aggressive computation (default 8 shards)";
          leaf shards {
            type uint16 { range "1..256"; }
            default 8;   // bare `sharding` => 8 (applied by the handler)
          }
        }
      }
    }
  }
}
```

CLI:

```
set router isis fast-reroute ti-lfa compute-mode aggressive
set router isis fast-reroute ti-lfa compute-mode sharding              # 8 shards
set router isis fast-reroute ti-lfa compute-mode sharding shards 4
```

(OSPFv2 / OSPFv3 carry the same nested shape — `compute-mode <mode>`
with the shard count under `compute-mode sharding shards <1..256>`.)

Handlers mirror `config_fast_reroute_backup_as_primary`
(config.rs:1345): store on `IsisConfig`
(`ti_lfa_compute_mode`, `ti_lfa_compute_shards`), trigger
`SpfCalc(L1)+SpfCalc(L2)` so the change is observable immediately
(results are identical across modes; the retrigger is for stats/BDD
determinism). No LSP re-origination — nothing advertised changes.
Mode is snapshotted into `SpfInput` at build time, so a mid-run config
change cleanly applies to the next run. Pin the new CLI paths with
`parse()` unit tests per repo convention.

## 9. Determinism and equivalence

All modes must produce identical `tilfa_result`:

- `spf_calc` is deterministic; every job is a pure function of
  `(graph, root, x, opts)`.
- I1 holds because `p_space_vertices`'s embedded SPF call is literally
  the primary SPF call (same graph/root/`SpfOpt::full_path()`/no
  `path_max`) — for both the legacy and MT2 pairs as passed by
  `compute_spf`.
- I2 holds because `pc_paths` only reads `d` *after* its SPF.
- Pre-existing caveat (not made worse): `first_hop_link_id` selection
  iterates a `HashSet` (calc.rs:555-559); with parallel equal-cost
  links to the same first hop the pick is arbitrary per HashSet
  instance. Sets are job-local in every mode, so the nondeterminism
  window is unchanged; equivalence tests use fixtures without parallel
  equal-cost links.

Tests:

- PR-A oracle tests (`spf/calc.rs`): assert
  `p_space_vertices(g, s, x) == p_space_from_spf(spf(g, s, full), s, x)`
  for every candidate `x` on all three fixtures (pins I1), and that the
  decomposed pipeline (`p_space_from_spf` + `q_space_vertices` +
  `spf_calc(x-excluded)` + `repair_from_parts`) equals `spf::tilfa`
  per destination (pins I2 + the extraction).
- `spf` unit (PR-B): for each fixture (`tilfa_graph`, `isis_lan_graph`,
  `mixed_lan_p2p_graph`) plus a batch of LCG-generated random graphs
  (no new dev-dependency; no parallel duplicate edges), derive targets
  IS-IS-style and assert every mode equals the `spf::tilfa` reference
  loop — serial, conservative, aggressive, sharding `K ∈ {1, 2, 7}`.
- Planner unit: grouping, LPT balance, `K >` group count, single group.
- BDD: extend `bdd/tests/features/isis_tilfa.feature` (or a sibling
  `@isis_tilfa_parallel` feature reusing its topology) with scenarios
  that set `compute-mode aggressive` / `compute-mode sharding shards 2`
  and assert the same repair output as the serial scenario; mandatory
  `Scenario: Teardown topology` per repo BDD rules.
- Perf harness: `#[ignore]`d test generating a ~24×24 grid graph and
  printing per-mode timings
  (`cargo test --release -p zebra-rs tilfa_perf -- --ignored --nocapture`).
  CI never runs it.

## 10. Observability

Extend the `show isis spf` SPF-stats block (show.rs:2876):

```
SPF stats:
  L1: last 12s ago, took 41ms, inflight=false, pending=false
      ti-lfa: targets=998 mode=aggressive workers=16 spf{q=998 pc=8 dedup-saved=990} took 38ms
```

plus a `tracing::debug!` line per run with the same fields. Stats ride
`SpfOutput` (legacy + MT2 summed).

## 11. Risks / notes

- **Memory**: aggressive holds `|X|` full-path PC trees concurrently
  (serial holds 1 transient). `|X|` ≤ neighbor count; a 1 000-vertex
  full-path tree is roughly hundreds of KB — bounded and acceptable.
  Sharding gives a hard `K`-proportional bound for memory-sensitive
  deployments.
- **ECMP path explosion** in `full_path` mode (`path_max: None`) is a
  pre-existing property of the primary SPF and per-target PC SPFs;
  exposure is unchanged in kind, only `|X|`-fold in liveness under
  aggressive.
- **Panic-wedge (pre-existing)**: the `spawn_blocking` JoinHandle is
  not awaited; a panic in `compute_spf` already loses `SpfDone` and
  wedges `spf_inflight` forever. The parallel arms keep panic-free
  discipline (no unwraps on shared state); a separate hardening
  follow-up should `catch_unwind` in the worker and always deliver a
  completion message.
- **rayon vs tokio**: rayon threads are separate from tokio workers;
  TI-LFA bursts are short. If contention ever shows, cap the global
  pool via `ThreadPoolBuilder::build_global` at startup (one-liner in
  `main.rs`, deferred until needed).

## 12. Rollout (small PRs)

1. **PR-A — spf refactor, no behavior change** (+ this doc): extract
   `repair_from_parts` + `p_space_from_spf`, derive `PartialEq`;
   `spf::tilfa` reimplemented on top; existing tests + new oracle
   tests pin equivalence.
2. **PR-B — modes + IS-IS wiring**: rayon dep, `spf/tilfa_par.rs`
   (modes, stats, planner helpers, equivalence tests), IS-IS
   `tilfa_targets` split, `SpfInput/SpfOutput` plumbing, YANG + config
   handlers + `parse()` tests, show output. Default `serial` = the
   2-SPF sequential loop (§6.0) — results identical, ~⅓ less CPU, no
   concurrency unless configured.
3. **PR-C — BDD + perf harness** (+ cross-link this doc).
4. **Later — OSPF series** (§13), then optional follow-ups (§14).

Each PR: `cargo fmt`, workspace clippy, full test suite before push.

## 13. OSPF follow-up (sketch)

`ospf/tilfa.rs:55 tilfa_repair_path` gets the same target-split and
calls the shared `spf::tilfa_compute`. One caveat: the OSPF primary SPF
runs in nexthop mode (`SpfOpt::default()`), so I1 does not apply
directly — phase A adds **one** shared full-path SPF from `s` on the
unmodified graph (it is `x`-independent), restoring the same
`N + |X| (+1)` count. Config knobs mirror under
`/router/ospf{,v3}/fast-reroute/ti-lfa`, generic over `Ospf<V>` per the
v2/v3 pattern. The two `spawn_blocking` SPF sites (ospf/inst.rs:4781,
:6868) are already shaped like IS-IS.

## 14. Future work (out of scope)

- Parallelize the top-level independent SPFs (MT2, per-flex-algo) in
  phase A alongside PC jobs.
- Flex-algo TI-LFA (currently not computed at all).
- Q-space sharing for multi-failure/SRLG `x`-sets (the reverse SPF is
  `x`-independent — filter-only reuse).
- Incremental TI-LFA (recompute only targets whose primary first-hop
  changed).
- Worker panic hardening (§11).

## 15. Decisions (resolved 2026-06-12)

1. **Substrate**: rayon.
2. **Default mode**: `serial`.
3. **No redundant calculation in any mode**: conservative runs 2 SPFs
   per target, and the same applies everywhere — `serial` is the
   sequential 2-SPF loop (§6.0), aggressive/sharding additionally dedup
   PC by `x`. The legacy 3-SPF path survives only as the `spf::tilfa`
   reference API (test oracle; OSPF until §13 lands).
4. **Shards default/range**: `8` / `1..256` (unobjected).
5. **Stats granularity**: legacy+MT2 merged (unobjected).
