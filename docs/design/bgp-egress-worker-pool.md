# BGP egress worker pool — logical engines on a fixed pool (§12 P3)

Status: **design proposal** (no code). The third axis of the egress story,
orthogonal to the other two design memos:

| memo | axis | question it answers |
|---|---|---|
| [`bgp-egress-journal.md`](bgp-egress-journal.md) | **feed** | how does a change reach the consumers — push (today) vs pull from a shared, bounded, GC'd journal (P1/P2) |
| [`bgp-egress-group-task-migration.md`](bgp-egress-group-task-migration.md) | **coalescing engine** | what is the unit of egress state + encode — per-peer (PET) vs per-`UpdateGroupSig` (one encode, fan to members) |
| **this memo** | **execution** | how many OS threads run how many engines — one task/thread per engine (today) vs many logical engines work-stolen onto a *fixed* pool |

This is `bgp-rib-sharding-plan.md` **§12 P3** ("decouple ownership granularity
from worker-thread count"). It composes with the other two — the journal is
the feed, the group `Engine` is the unit scheduled — and it does **not**
re-derive either; read those first.

## Decisions (proposed — to lock before any code)

1. **The `Engine` is the fixed point.** Today's `group_egress.rs::Engine`
   (`{ members, add_path, adj_out, attr_store }`, with `advertise` / `withdraw`
   / `record_adj_out` / `fan`) is the right ownership domain and is **reused
   byte-for-byte**. This memo changes only *where it runs*, never the per-delta
   logic. Its unit tests carry over unchanged.
2. **`K` execution threads, `M` logical engines, `K ≪ M` allowed.** A fixed
   pool of `K = ZEBRA_BGP_EGRESS_WORKERS` OS threads (default
   `max(1, cores − shards − 1)`) schedules `M` engines (one per `UpdateGroupSig`,
   or per peer for the PET case). `M` may be 1 or 500 and may change at runtime;
   `K` does not move with it.
3. **Work-stealing, not static affinity.** An engine is a *schedulable unit*
   pulled from a shared deque, not a thread-pinned actor. This is the explicit
   rejection of the naive §12-P1 "one OS thread per group," whose static
   affinity load-balances badly on non-uniform groups (§3).
4. **Per-engine serialization preserved** — at most one pool thread runs a given
   engine at a time (the slot lock / single-runnable flag), so the engine's
   single-threaded invariants (`adj_out` ptr-eq dedup, per-prefix order) hold
   exactly as under its dedicated task today.
5. **Env-gated, parity-checked, v4-unicast first** — same discipline as the PET,
   the group task, and the journal. Gate-off (update-group flush) is untouched.

## 1. The defect this axis owns

The other two memos leave one thing fixed at **1:1**: the number of egress
**engines** is the number of **executors**.

- **Group task today** (`group_egress.rs`): `attach` **spawns one tokio task per
  `UpdateGroup`**, `detach` aborts it. `M` groups ⇒ `M` tasks on the tokio
  runtime.
- **PET today** (`peer_egress.rs`): one tokio task per Established peer. 2000
  peers ⇒ 2000 tasks.
- **The naive §12-P1 "Juniper U-threads"**: `M` *dedicated OS threads* with
  static group→thread affinity.

All three couple the count of ownership domains to the count of executors. That
is fine on the tokio runtime for modest `M` (tokio multiplexes tasks onto its
worker pool already), but it is **wrong for the dedicated-thread form** that
would actually give egress CPU isolation off the runtime — there, `M` OS
threads compete with the `N` shard threads + main + I/O for `C` cores, and:

- `M` is **not** sized to cores (it is sized to the peering topology);
- `M` changes at runtime (regroup, peer up/down) ⇒ thread spawn/teardown churn;
- groups are **non-uniform** (one 1000-member eBGP group, one 1-member iBGP
  group), so static affinity makes one thread hot while others idle;
- an idle group still holds a thread.

P3 keeps the *ownership* fine-grained and dynamic (one engine per group) while
making the *execution* a small, fixed, cores-sized, work-balanced pool.

## 2. The design

### 2.1 Registry, not task-per-engine

Replace `UpdateGroup.task: Option<GroupEgressTask>` (a per-group tokio task)
with a passive slot in a shared registry:

```rust
struct GroupSlot {
    engine:   Mutex<Engine>,   // the SAME Engine as group_egress.rs today
    runnable: AtomicBool,      // is it (or about to be) in the run-queue? dedups re-enqueues
    cursors:  Vec<Seq>,        // one read-cursor per shard journal (the feed memo)
}

struct EgressRegistry {
    slots: RwLock<BTreeMap<UpdateGroupId, Arc<GroupSlot>>>,  // attach/detach mutate
    runq:  crossbeam::deque::Injector<UpdateGroupId>,         // global injector + per-worker steal
    park:  Condvar,                                           // workers sleep when runq empty
}
```

`attach` / `detach` no longer spawn / abort a task — they insert / remove a
`GroupSlot` (O(log M), no thread lifecycle). The membership deltas
(`AddMember` / `RemoveMember`) and the show queries (`DumpAdjOut` /
`CountAdjOut`) stay exactly as `GroupEgressDeltaV4` variants — they are just
enqueued as control items the scheduler runs on a pool thread under the slot
lock, instead of riding a per-task channel.

### 2.2 The work-stealing pool (mirrors `ShardPool`)

`K` OS threads spawned like `shard/pool.rs::ShardPool::spawn` — blocking
threads off the tokio runtime, for the same CPU-isolation reason
(`pool.rs:7-9`). The unit pulled is a *group id*, not a pinned `BgpShard`:

```rust
fn worker_loop(reg: Arc<EgressRegistry>) {
    loop {
        let gid = match reg.steal_runnable() {      // local deque → global injector → steal peers
            Some(g) => g,
            None    => { reg.park_until_signalled(); continue }
        };
        let slot = reg.slot(gid);
        let mut eng = slot.engine.lock();           // exclusive ⇒ per-engine serialization (Decision 4)
        drain_into(&mut eng, &slot.cursors);        // pull from journals + advertise/withdraw + fan
        slot.runnable.store(false, Release);
        if behind_head(&slot.cursors) {             // appends arrived mid-drain
            reg.enqueue(gid);                        // re-arm; never busy-spin
        }
    }
}
```

This is `ShardWorker::run` (`pool.rs:53`) with the inbox replaced by a
work-stealing deque of runnable engines. Number of threads is fixed; number of
engines is whatever the topology produces.

### 2.3 The feed (the journal memo, in one paragraph)

`drain_into` is where this memo meets [`bgp-egress-journal.md`](bgp-egress-journal.md):
the engine pulls best-path changes from the shared journal(s) past its cursor
and runs **today's `Engine` code unchanged**:

```rust
for d in journal.since(cursors) {                 // (prefix, Option<Arc<BgpRib>>, source_ident)
    match d.best {
        Some(rib) => eng.advertise(d.prefix, rib),    // ← group_egress.rs, unchanged
        None      => eng.withdraw(d.prefix, 0, d.source_ident),
    }
    cursors.advance(d.seq);
}
```

The pool is feed-agnostic: against the journal it pulls; as a first cut it can
just as well be fed by today's `fan_advertise_to_groups` enqueuing
`(gid, Advertise)` control items (the pool then schedules the engine). The
journal is the *better* feed (O(1) on main, bounded, skip-on-read coalescing),
but the pool lands independently of it.

## 3. Why work-stealing beats static affinity here

The naive P1 pins group → thread. That is wrong because group **build cost** and
group **count** are both uneven and unbounded:

- **Build cost is per-(prefix, group), not per-member.** A 1000-member group
  encodes each prefix **once** and `fan`s 1000 cheap byte-clones; a 1-member
  group encodes the same prefix once. So member count drives only the (cheap)
  fan. The real imbalance is *how many prefixes a group advertises* — heavy
  out-policy-deny groups advertise few. Static affinity pins that imbalance to a
  thread; **work-stealing rebalances it** — a group that is behind stays in the
  deque and any free worker grabs it.
- **Count is topology-driven.** `M` can be ≫ cores. One-thread-per-group either
  over-subscribes (`M` threads on `C` cores — the §"no spare cores" knee the
  sharding plan measured at N=4) or, on tokio, reintroduces runtime contention
  with the I/O tasks. A fixed `K`-thread pool sizes to cores regardless of `M`.

This is exactly what GoBGP (2048 ownership domains over `GOMAXPROCS` goroutines)
and BIRD (`birdloop` balancer work-stealing many loops onto a fixed thread pool)
do, and why §11 notes **neither uses a fixed dedicated egress *thread* pool** —
they decouple ownership from execution, which is this memo.

## 4. Ordering & correctness

- **Per-engine serialization** — the slot `Mutex` + `runnable` flag guarantee at
  most one worker runs an engine at a time, so `Engine`'s single-threaded
  invariants (the `adj_out` ptr-eq dedup, encode-once, split-horizon source)
  are unchanged from its dedicated-task life today.
- **Per-(peer, prefix) order** — one prefix → one shard → one journal (monotonic
  `seq`); the engine drains each journal in `seq` order. announce-before-withdraw
  for a prefix holds within that stream. Cross-prefix order is irrelevant to BGP.
  As the journal memo notes (§7), this makes the main-side cross-shard hazard
  machinery (`flush_inflight` + `deferred_withdraw_ipv4`) **unnecessary** in this
  model — the journal *is* the order.
- **Membership vs delta race** — `AddMember` / `RemoveMember` run under the same
  slot lock as the drain, so a member set never changes mid-`fan`. A new member
  is caught up by the journal cursor + the existing `RecordAdjOut` path, exactly
  as in the group task today.
- **Re-arm correctness** — a worker that finishes a drain re-checks `behind_head`
  *before* clearing `runnable`; the enqueue-on-append + this re-check together
  guarantee no change is left unserved (the standard actor-scheduler wakeup
  invariant).

## 5. Backpressure & the cores knob

- **Backpressure** is the journal's (watermark + overrun→resync,
  `bgp-egress-journal.md` §5); the pool inherits it — a slow engine simply lags
  its cursor and, past the watermark, re-syncs via `DumpV4`. The pool adds no new
  unbounded queue (the run-queue holds *group ids*, deduped by `runnable`, so it
  is ≤ `M` entries).
- **The cores knob becomes a clean pair.** Total threads = `N` (shards) + `K`
  (egress) + 1 (main) + tokio I/O. With P3, `K` is fixed and small, **independent
  of `M`** — so the operator tunes one `shards`-vs-`egress-workers` split against
  `C`, exactly Juniper's shards-vs-update-threads, and it does not blow up when
  the peering grows. Today's bounded rayon egress pool (E.2) already does this
  *split* elastically for the out-policy precompute; P3 extends the same
  fixed-budget discipline to the bucketing/encode/adj-out the rayon pool can't
  own across calls.

## 6. What's reused vs new

| | |
|---|---|
| **Reused unchanged** | `Engine` + all its methods + its unit tests; `GroupEgressDeltaV4` (now control/query items, not a per-task channel); `RecordAdjOut` late-member catch-up; the `DumpV4` spawn/soft-out resync; the `ShardPool` spawn idiom |
| **New** | `EgressRegistry` (slot map + run-queue); the `K`-thread `EgressPool`; `GroupSlot` (engine + cursors + runnable); the work-stealing scheduler + wakeup |
| **Deleted** (at gate-on) | the per-group `GroupEgressTask` spawn/abort in `attach`/`detach`; (with the journal) `fan_advertise_to_groups` + the main-side deferred-withdraw machinery |

Net: the hard, already-correct part (`Engine` — split-horizon source, intern
dedup, encode-once-fan, AddPath candidates, late-member `RecordAdjOut`) is the
fixed point; the diff is a scheduler + a registry around it.

## 7. Honest hard parts

- **The scheduler is the new correctness surface.** Lock-free deque +
  `runnable` flag + re-arm + park/unpark is a classic actor scheduler — small,
  but the wakeup invariant (no missed re-arm, no lost wakeup, no busy-spin) must
  be unit-tested hard. Start with a `Mutex<VecDeque>` + `Condvar` if crossbeam's
  deque isn't worth the risk in v1; the API (enqueue / steal / park) is identical.
- **Slot-lock contention** — a show query or membership change locks the engine
  and briefly blocks a worker from running that group. Rare; acceptable. If it
  isn't, route queries through the journal/run-queue as control items (no direct
  lock).
- **Wake amplification** — one journal append must not enqueue all `M` engines
  to each read one entry. The `runnable` dedup + a small debounce on the append
  signal (the update-group flush self-message pattern) batch it so each engine
  drains *runs* of entries per wake.
- **Cross-runtime hand-off** — a std::thread worker sends encoded bytes to a
  peer's tokio writer task via the existing `packet_tx` (the shards→main result
  channel precedent). One channel hop per send; already how `SyncCtx::send_packet`
  works, so no new boundary.
- **It only pays at scale.** Like all of Phase E, the win needs RR-scale fan-out
  + many engines; at BDD/2-peer scale it is neutral-to-negative. BDD is the
  correctness gate, the §9 matrix is the perf gate.

## 8. Phased delivery (env-gated, parity-checked)

Sequenced **after** the journal (it is the feed) but the pool itself can land on
the push feed first:

- **Phase P0 — registry + pool on the push feed.** `EgressRegistry` + `EgressPool`
  running the existing `Engine`, fed by `fan_advertise_to_groups` enqueuing
  control items instead of `task.send`. Behaviour identical to the per-group
  task; prove against `@bgp_egress_group_task` / `@bgp_egress_group_sharded` /
  `@bgp_addpath_group`. New sub-gate `ZEBRA_BGP_EGRESS_POOL` under the group
  gate. This is the **execution** change in isolation — no journal yet.
- **Phase P1 — pull from the journal.** Swap the feed to
  `bgp-egress-journal.md` cursors once that lands; the pool's `drain_into`
  becomes a journal pull. Deletes `fan_advertise_to_groups` + the deferred-
  withdraw machinery at gate-on.
- **Phase P2 — scheduler hardening + matrix.** Work-stealing (crossbeam) +
  wake debounce + the slow-engine BDD (wedge one group's drain, assert others
  converge + run-queue stays bounded) + the perf matrix at
  `shards × egress-workers × groups`, picking the cores-split default.

Each phase is gate-on-only and leaves gate-off (update-group flush) and the
per-group-task path byte-identical until retired.

## 9. Recommendation

Build P0 (pool on the push feed) **only after** the group task is a candidate
for the default egress and the journal (`bgp-egress-journal.md` J0–J2) is in
flight — at that point the per-group *task* count is the next thing that does
not scale, and the pool fixes it without touching the proven `Engine`. Until
then the per-group tokio task is fine (tokio already multiplexes modest `M`
onto its workers); P3 earns its complexity only when egress wants **dedicated,
cores-budgeted CPU off the runtime** (the dedicated-thread form), at which point
work-stealing — not static affinity — is the only shape that survives
non-uniform, dynamic, count-unbounded groups.

Ordering of the three egress memos, then: **journal (feed) → group task
(coalescing engine) → this pool (execution)** — each independent enough to land
alone, together the full §12-P1+P3 Juniper update-worker form, minus the static
affinity Juniper itself doesn't actually need.
