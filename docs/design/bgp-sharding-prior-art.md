# BGP RIB Parallelism: Prior Art (BIRD 3.x & GoBGP)

Status: **Reference memo.** Two other open BGP stacks — BIRD 3.3.0 and
GoBGP — were read in full to place zebra-rs's RIB-sharding design. This
memo is the companion to [`bgp-rib-sharding-plan.md`](bgp-rib-sharding-plan.md)
(it was extracted and expanded from that doc's §11); the plan owns the
zebra-rs design and delivery, this memo owns the comparison.

The sharp question throughout: **how does each stack parallelize a single
BGP table's work** — best-path selection and advertise? There are three
different answers, and the differences are exactly the design space the
sharding plan navigates.

## Source pins

| Stack | Path | Version | Branch | HEAD |
|---|---|---|---|---|
| BIRD | `/home/kunihiro/bird` (`../bird`) | 3.3.0 | `stable-v3.3` | `10682b7b` |
| GoBGP | `/home/kunihiro/gobgp` (`../gobgp`) | `gobgp/v4` | `master` | `7204bf9d` |

All `file:line` anchors below were verified against these exact
checkouts. Line numbers drift across commits — if one misses, **grep the
named symbol**, don't trust the number.

## The three answers at a glance

- **BIRD 3.3** parallelizes *across* tables and protocols, never *within*
  one table. A single table's best-path is **serial** under one per-table
  lock; the win is that **reads are lock-free** (RCU caches) and **egress
  is parallel per consumer** via lock-free journals.
- **GoBGP** shards a single table by prefix hash across **2048 bucket
  *locks*** over shared memory. Best-path runs in parallel across
  prefixes, but inside a lock, with cache-coherency traffic on every
  update.
- **zebra-rs** shards a single table by prefix hash into **owned** shard
  threads — shared-nothing, **no hot-path locks**, main↔shard by message
  passing. (See the plan.)

```
                 within-one-table best-path        egress (advertise)
BIRD 3.3         serial (1 lock/table)             parallel per consumer (journal pull)
GoBGP            parallel under 2048 bucket locks  parallel per peer (encode only)
zebra-rs         parallel, owned shards, no locks  serial reduce → Phase E
```

---

## BIRD 3.3 — per-protocol / per-table loops, serial within a table

BIRD 3 is a ground-up multi-threaded redesign (2.x was a single event
loop). Its concurrency unit is the **`birdloop`**; parallelism comes from
running many loops on a thread pool, **not** from sharding any one table.

### Threading model — thread pool + `birdloop`

A fixed pool of OS threads is created per *thread group*:
`bird_thread_start` → `pthread_create(..., bird_thread_main, thr)`
(`sysdep/unix/io-loop.c:1253`). Each thread runs an infinite scheduler
(`bird_thread_main`, `io-loop.c:977`): fire meta timers → run the
balancer → run its assigned loops → `poll()` their sockets.

A `birdloop` (`sysdep/unix/io-loop.h:44`) is the unit of single-threaded
execution — an event list, timers, socket list, a pool, and **its own
lock domain** (`domain_new(order)` in `birdloop_vnew_internal`). Within
one loop run (`birdloop_run`) everything is serialized; concurrency is
*between* loops.

A **work-stealing balancer** (`birdloop_balancer`, `io-loop.c:832`) runs
once per scheduler iteration: each thread claims a proportional batch of
unassigned loops from its group's shared pickup list, and an overloaded
thread *drops* loops back for others to steal. Loop↔thread reassignment
is an atomic handshake (`birdloop_set_thread`, `io-loop.c:717`). Two
implicit groups exist: **worker** (300 ms slice) and **express** (10 ms).

### Unit of concurrency — per-protocol loop + per-table service loop

- **Each protocol instance gets a loop.** `proto_new` →
  `birdloop_new(...)`, stored as `p->loop` (`nest/proto.c:1568`).
  *Caveat:* a protocol with `loop_order == DOMAIN_ORDER(the_bird)` runs
  on the shared `&main_birdloop` instead (`proto.c:1561`) — protocols are
  not *guaranteed* a private loop.
- **Each table gets its own *service* loop** (`rt_setup` →
  `birdloop_new(..., DOMAIN_ORDER(service), ...)`, `nest/rt-table.c:3808`)
  **and a *separate* data lock** at `rtable` order
  (`DOMAIN_NEW(rtable)`, `rt-table.c:3813`; field at `nest/route.h:383`).
  Two domains, deliberately split (see lock order below).

The service loop handles only table-internal maintenance — prune,
next-hop update, hostcache, journal cleanup. It does **not** run
best-path.

### Best-path within one table — serial, no per-prefix sharding

> **Correction to the older §11 framing:** best-path is *not* "run on the
> table's service loop." It runs under the per-table **`rtable` lock**,
> and that lock is taken **by the importing protocol's own loop** (e.g.
> BGP's UPDATE parser), not by a single owning thread.

`rte_recalculate` (`nest/rt-table.c:2325`) does the election. The call
path: `rte_update` (`:2672`) runs the **in-filter before locking**
(`f_run`, `:2706`), then `rte_import` (`:2756`) opens
`RT_LOCKED` — `#define RT_LOCKED ... LOCK_DOMAIN(rtable, ...)`,
`nest/route.h:470` — at `rt-table.c:2765`, interns the prefix, resolves
the slot, and calls `rte_recalculate` (`:2836`), all in one critical
section. `rte_update` is invoked from the protocol's own loop
(`proto/bgp/packets.c:1634`). Election compares via `rte_better`
(`rt-table.c:1120`) and publishes the new best with an atomic store.

**There is no per-prefix sharding within a table.** Storage is a single
flat `_Atomic`-pointer array indexed by a table-wide netindex, guarded by
one whole-table lock (`struct rtable_private`, `nest/route.h:396`, has no
striped lock array). The atomics + `synchronize_rcu()` inside
`rte_recalculate` exist so lock-free *readers* can traverse concurrently
with the single locked writer — they are not a write-sharding mechanism.
**Intra-table best-path is single-threaded; BIRD's parallelism is across
tables/protocols and on the export side.**

### Egress / advertise — lock-free journals (`lfjour`)

This is where one table's work *does* go parallel. Each table has **two**
lock-free journals (`nest/route.h:392-393`): `export_all` (every change)
and `export_best` (best-path changes only); a consumer subscribes to one
per its `ra_mode` (`nest/proto.c:892`).

- **Write side** (producer, under the table lock): `rte_announce_to`
  (`rt-table.c:2034`) → `rt_exporter_push` (`nest/rt-export.c:476`) →
  `lfjour_push_prepare`/`_commit` (`lib/lockfree.c:62-138`). A settle
  timer on the table loop coalesces pushes before pinging consumers.
  `lfjour_push_prepare` returns NULL when there are **no recipients and
  nothing pending** — no work when nobody listens.
- **Pull side** (consumer, on its *own* protocol loop): the recipient
  event drains via `rt_export_get` (`nest/rt-export.c:38`) → `lfjour_get`
  (`lib/lockfree.c:179`, RCU-guarded). **The export filter and the
  protocol encode run here, on the consumer loop:** `export_filter`/
  `f_run` (`rt-table.c:1269`) → `bgp_rt_notify` (`proto/bgp/bgp.c:3105`).
  The recipient's wakeup target is the consumer's own loop
  (`proto_work_list` = `birdloop_event_list(p->loop)`,
  `nest/protocol.h:264`; set at `proto.c:863`).

So with N peers there are **N loops filtering + encoding concurrently**,
each pulling the same journal locklessly. (Cleanup/retirement of consumed
items happens back on the table loop under RCU, `lfjour_cleanup_hook`,
`lib/lockfree.c:455`.)

### Lock-free reads — RCU attribute cache + netindex interning

Neither read path takes the table lock:

- **Attribute cache** (`nest/rt-attr.c`): a global RCU hash
  (`rt-attr.c:1911`); lookup `ea_find_in_array` (`:1998`) is a pure
  atomic chain walk under `rcu_read_lock` (`ea_lookup_slow`, `:2146`);
  insert publishes by CAS; refcounts are atomic (`ea_storage.uc`,
  `lib/route.h:293`) with RCU-deferred free. The `attrs`-domain mutex
  (`RTA_LOCK`, `lib/route.h:97`) is taken only for oversized allocations,
  never on the lookup/insert hot path.
- **Netindex prefix interning** (`lib/netindex.c`): `net_find_index`
  (`:298`) is RCU + atomics; the `NH_LOCK` mutex (`attrs` order) is taken
  only to insert a *new* prefix (`net_get_index`, `:306`). *Nuance:* the
  lookup additionally takes a per-bucket read **spinlock** (`SPINHASH`,
  `lib/hash.h:269`), so it is not as purely lock-free as the attr cache.

### Lock domain order

A strict global order prevents deadlock when a protocol loop descends
into table data and the caches (`lib/locking.h:19`):

```c
#define LOCK_ORDER \
  the_bird, meta, control, proto, subproto, \
  service, rtable, attrs, logging, resource,
```

`do_lock` (`sysdep/unix/domain.c:103`) maintains a thread-local stack and
`bug()`s on out-of-order acquisition; it also forbids taking any lock
below `resource` while an RCU reader is active. An importing protocol can
therefore hold its own (`proto`/`subproto`) domain, then take the table's
`rtable` lock, then intern into `attrs` — strictly increasing, never
inverting. Two domains per table (service loop @ `service`, data @
`rtable`) is what lets protocol loops cross into table data cleanly.

```
peer A loop ─┐                         ┌─ peer X loop  (pull export_best,
peer B loop ─┤  rte_update (in-filter  │   filter + bgp_rt_notify encode,
peer C loop ─┘  on its OWN loop)       │   ON ITS OWN LOOP)
       │                               │
       ▼  take per-table rtable lock   │   lock-free journal pull (RCU)
   ┌───────────────────────────────┐   │
   │  TABLE (one rtable lock)       │──lfjour──▶ export_all / export_best
   │  rte_recalculate  [SERIAL]     │   │
   └───────────────────────────────┘   └─ peer Y loop  (concurrent with X)
   reads (attr cache / netindex): RCU, no table lock
```

---

## GoBGP — per-peer goroutines + prefix-hash *lock* sharding

GoBGP recently retrofitted prefix-hash sharding (commit `4be569ad`,
"feat: propagateBucket", 2026-04-27) — convergent with the zebra-rs
direction, but via **locks over shared memory** rather than ownership.

### Goroutine model — per-peer, and the central `Serve()`

Each Established peer runs **three** goroutines (all from `fsmHandler`):

- **FSM loop** (`fsm.go:826`) — the `idle→…→established` state machine.
- **recv goroutine** (`recvMessageloop`, spawned `fsm.go:1995`) — does
  the **wire decode** on this goroutine (`DecodeFromBytes`,
  `fsm.go:1291`), then calls `h.callback(fmsg)` (`fsm.go:1968`).
- **send goroutine** (`sendMessageloop`, spawned `fsm.go:1994`) — see
  egress below.

The central **`Serve()`** loop (`pkg/server/server.go:383`) is a single
goroutine that selects on only three channels — management ops, accepted
connections, and ROA — each under `shared.mu` **write** lock. **Inbound
UPDATEs never pass through `Serve()`.**

> **Key finding:** `callback` is a *synchronous* function call, not a
> channel hop. It is wired to `handleFSMMessage` (`server.go:285`), so an
> inbound UPDATE is processed **on the peer's own recv goroutine**.
> `handleFSMMessage` takes only `shared.mu.RLock()` (`server.go:1551`),
> so **all peers' recv goroutines process inbound UPDATEs concurrently**
> with each other — serialized only against `Serve()`'s write-lock ops.

### Prefix-hash sharding — 2048 bucket mutexes

`sharedData` holds `propagateBuckets [2048]sync.Mutex`
(`propagateBucketCount = 2048`, `server.go:112`). `propagateBucket(path)`
picks one via `farm.Hash64(family+prefix) % 2048` (`server.go:125-132`).
`propagateUpdate` (`server.go:1189`), per path, does
`bucket.Lock()` (`:1222`) and under it runs import policy (`ApplyPolicy`
`POLICY_DIRECTION_IMPORT`, `:1241`), best-path (`rib.Update`, `:1266`),
and the cross-peer fan-out (`:1267`).

The hash key is the `(family, prefix)` *local key*, deliberately matching
the per-peer RIB-out index `peer.sentPaths` (`peer.go:99-117`): the
bucket lock provides **prefix-level mutual exclusion spanning both the
Loc-RIB update and every target peer's RIB-out state** for that prefix.
Different prefixes → different buckets → full parallelism across the
concurrent recv goroutines; the **same prefix is serialized** regardless
of which peer it arrived on.

### Not a "per-destination lock" — three nested lock levels

> **Correction to the older §11 framing:** there is **no per-`Destination`
> mutex**. Under the bucket lock sit two more levels, and the innermost
> is itself a 2048-way shard:

```
shared.propagateBuckets[hashA]   per (family+prefix)      server.go:1222
  └─ manager.mu.RLock()          TableManager RWMutex     table_manager.go:247
       └─ destinationShard.mu[hashB]  per-NLRI-hash (2048) table.go:461
            └─ destination       (no lock; guarded by the shard)
```

`destinationShardCount = 2048` (`internal/pkg/table/table.go:103`);
`Table.update` (`:454`) picks a shard by a *separate* FNV-1a hash of the
NLRI (`getShard`, `:120`) and locks `shard.mu` for the whole op. The
`destination` struct itself has no lock (`destination.go:205`); its doc
comments say it is protected by "the appropriate shard lock." `hashA` and
`hashB` are different hash functions on different keys — two independent
shardings layered on top of each other.

### Best-path — on the recv goroutine, inside the locks

`Destination.Calculate` (`internal/pkg/table/destination.go:307`) runs
inside all three locks, on the producing peer's recv goroutine. Election
is an inline `insertSort` (`:424`) keeping `knownPathList` sorted
best-first via the full comparator ladder (reachable-nexthop → weight →
LocalPref → AS-path → origin → MED → eBGP/iBGP → IGP cost → router-id).
So the older §11 framing — *best-path + import policy on the per-peer
recv goroutine, parallel across prefixes, inside the bucket lock* — is
**correct** (with the refinement that "the bucket lock" is really the
three nested levels above).

### Cross-peer fan-out + egress encode

> **Correction to the older §11 framing:** egress is parallel per peer
> only for the **encode + TCP write**. The **export *policy* and the
> fan-out loop run on the *producer's* recv goroutine**, serially, inside
> the bucket lock — not on each target's send goroutine.

`propagateUpdateToNeighbors` (`server.go:1383`, called at `:1267`) loops
over `s.neighborMap` (`:1395`) **serially within the bucket lock**. For
each target it applies **export policy** (`filterpath` → `ApplyPolicy`
`POLICY_DIRECTION_EXPORT`, `server.go:1109`), updates that target's
RIB-out (`updateRoutes`, legal because still under the prefix's bucket
lock), then hands the result off via `sendfsmOutgoingMsg` →
`fsm.outgoingCh.In() <- ...` (`server.go:455`). `outgoingCh` is a
**per-peer unbounded `InfiniteChannel`** (`eapache/channels`, created at
`fsm.go:1568`).

The target's **send goroutine** (`sendMessageloop`, `fsm.go:1756`) then
dequeues, **coalesces** up to `maxCoalesceMsgs = 2048` batches
(`fsm.go:1818`), **encodes** (`CreateUpdateMsgFromPaths`, `fsm.go:1850`,
def `internal/pkg/table/message.go:694`), and writes to the socket
(`fsm.go:1769`). Encode + write are therefore fully parallel per peer.

```
peer A recv goroutine ──┐
peer B recv goroutine ──┤ propagateUpdate(path):
peer C recv goroutine ──┘   bucket.Lock(hash(family+prefix))   [1 of 2048]
        (concurrent for       ├─ import policy
         distinct prefixes)   ├─ rib.Update → Destination.Calculate  [best-path]
                              └─ propagateUpdateToNeighbors  [SERIAL fan-out:
                                     per target: EXPORT POLICY + RIB-out update]
                                        │ sendfsmOutgoingMsg → outgoingCh (per peer)
                                        ▼
   peer X send goroutine ── coalesce(2048) + encode + write   ┐ parallel
   peer Y send goroutine ── coalesce(2048) + encode + write   ┘ per peer
```

---

## zebra-rs — prefix-hash *ownership* sharding (shared-nothing)

For contrast (the full design is in the
[plan](bgp-rib-sharding-plan.md)): N dedicated OS threads each **own** a
prefix-hash slice of the Loc-RIB — no shared table, **no locks on the hot
path**; main↔shard is message passing (`RouteBatch` in, `ShardResult`
out). Best-path + inbound policy run inside the owning shard. Advertise
runs on the main **reduce** today; Phase E.1 parallelizes its out-policy
precompute (rayon, cost-gated), and Phase E.2 will move egress to
dedicated update-worker threads.

## The picture

| | BIRD 3.3 | GoBGP | zebra-rs |
|---|---|---|---|
| Concurrency unit | loop (per-proto, per-table) | per-peer goroutine + 2048 lock-buckets | per-prefix-hash **owned** shard thread |
| Single table's best-path | **serial** (one table lock) | parallel (2048 bucket + shard locks) | parallel (owned shards) |
| RIB memory model | shared, RCU reads + domain locks | shared, 2048+2048 nested mutexes | **partitioned, shared-nothing** |
| Hot-path lock cost | RCU reads lock-free; table write serial | mutex + cache-coherency per update | **none** (message passing) |
| Where inbound policy runs | importing protocol loop (before lock) | producing recv goroutine (in lock) | owning shard thread |
| Where export policy runs | **consumer loop** (parallel, journal pull) | **producer recv goroutine** (serial fan-out) | main reduce → E.1 parallel → E.2 workers |
| Egress encode / write | parallel per consumer loop | parallel per peer (send goroutine) | off-thread since Phase A; E.2 workers |
| Prefix interning | global RCU cache (shared) | shared table | per-shard (duplicated) |

## The sync path — initial feed of the Loc-RIB to a new peer

Everything above compares **steady-state** parallelism (best-path, egress
fan-out). A second axis matters directly for the plan's B.4 work: when a
peer reaches **Established**, how does each stack walk the existing
Loc-RIB and feed it to that *one* new peer? The shapes diverge more here
than in steady state.

```
                 dump read             who runs the build        per-peer parallel?
BIRD 3.3         resumable cursor      protocol's own birdloop    yes (loops on a pool); 1 peer serial
GoBGP            one-shot best list    per-peer FSM goroutine      yes (RLock); 1 peer serial
zebra-rs         one-shot Vec collect  single main task            NO — all peers serialize on main
```

| Dimension | zebra-rs | BIRD 3.3.0 | GoBGP (master) |
|---|---|---|---|
| Trigger | FSM→Established → `route_sync()` (`route.rs:9600`, from `peer.rs:1484`) dispatches `route_sync_<af>` | `proto_notify_state(PS_UP)` → `channel_start_export` (`nest/proto.c:1195`) → `rt_export_subscribe` | `fsmHandler.loop` → `handleFSMMessage` ESTABLISHED (`server.go:1716`) → `getBestFromLocalCallback` |
| Loc-RIB read | one-shot `Vec` (AddPath cands `.0` / best `.1`) | resumable cursor `rt_export_get` (`rt-export.c:39`), per-net `feed_index` | one-shot under `RLock`: `GetBestPathList` / `GetPathList` |
| Threading | **single main task**; v4 read via `mirror_v4` | per-protocol `birdloop` on a thread pool; `MAYBE_DEFER_TASK` yields | per-peer FSM goroutine under `s.shared.mu.RLock`; encode on `sendMessageloop` |
| Adj-RIB-Out | always-on `peer.adj_out.<af>` | opt-in (`export table`→`tx_keep`); else journal-driven | none persistent; `sentPaths` map |
| Batch / coalesce | per-attr buckets (`send_ipv4_direct`) | attr buckets (`bgp_get_bucket`) → max packet (`bgp_create_update`) | attr "cages" + ≤2048-msg coalesce (`CreateUpdateMsgFromPaths`) |
| Backpressure | unbounded `packet_tx` (encoded) → TCP at writer | TCP pauses/resumes `bgp_fire_tx` (bounded) | unbounded `InfiniteChannel` (paths) → TCP at `sendMessageloop` |
| End-of-RIB | **always**, per family (`send_eor_<af>`) | only under graceful-restart | only under GR / RTC (`table.NewEOR`) |

**BIRD — resumable cursor on the protocol's own loop.**
`bgp_conn_enter_established_state` calls `proto_notify_state(PS_UP)`; the
channel goes `CS_UP` and `channel_set_state` calls `channel_start_export`
(`nest/proto.c:1195`), which subscribes an `rt_export_request` to the
table's exporter. There is **no** BGP-specific "feed begin" — the old
`bgp_feed_begin` is gone; BGP only registers
`rt_notify`/`export_fed`/`refeed_begin` in `bgp_init` (`bgp.c:3105`). The
feed is a **resumable cursor**: `rt_export_get` (`nest/rt-export.c:39`)
drives `rt_export_get_next_feed`, advancing a `feed_index` one *net* at a
time off the shared table's export journal, so a huge dump cooperatively
yields (`MAYBE_DEFER_TASK`, `lib/io-loop.h:32`, at the tail of
`channel_notify_any`) and resumes next loop pass. It runs on **the BGP
protocol's own `birdloop`**, picked up by a pool thread (`bird_thread_
main`, `birdloop_take_one`): one peer is one-route-at-a-time, but
**different peers feed concurrently** on different cores. A persistent
Adj-RIB-Out exists only with the `export table` knob (`tx_keep`,
`bgp.c:3213`); by default `bgp_done_prefix` (`attrs.c:2413`) frees the
prefix after send and later withdraws ride the journal. EoR is emitted
**only under graceful-restart** (`BFS_LOADING`→`BFS_LOADED` in
`bgp_export_fed`, then `bgp_create_end_mark` in `bgp_fire_tx`).

**GoBGP — one-shot best-path list on the per-peer goroutine.** The
per-peer FSM goroutine `fsmHandler.loop` (`fsm.go:2119`) signals
Established by calling `h.callback` **directly** — *not* through the
central `Serve()` select loop, which only handles mgmt/accept/ROA. That
callback is `handleFSMMessage` (`server.go:1548`); its ESTABLISHED branch
(`server.go:1716`) calls `getBestFromLocalCallback(..., addEOR,
routeRefresh)`, which reads the Loc-RIB **once** under `manager.mu.RLock`
(`GetBestPathList`, or `GetPathList` when ADD-PATH send is on), runs
**export policy on this same goroutine** (`filterpath` →
`ApplyPolicy(EXPORT)`), then `sendfsmOutgoingMsg`. Because it holds a
*read* lock, **two peers' dumps run concurrently**; only config mutations
(write lock) serialize against them. There is **no persistent
Adj-RIB-Out** — a `sentPaths sync.Map` records path-ids (`updateRoutes`,
`peer.go:258`) for the withdraw decision, and a full `AdjRib` is rebuilt
transiently only for gRPC monitoring (`UpdateAdjRibOut`, `adj.go:113`).
The path list crosses an **unbounded `InfiniteChannel`** to a separate
`sendMessageloop` (`fsm.go:1756`) that coalesces ≤2048 messages and packs
same-attribute "cages" (`CreateUpdateMsgFromPaths`, `message.go:694`).
EoR is a sentinel `table.NewEOR` path appended only under GR or RTC.

**zebra-rs — one-shot collect on the single main task.** `route_sync`
(`route.rs:9600`, from the FSM at `peer.rs:1484`) dispatches
`route_sync_<af>` per negotiated family. Each collects the whole family
table from `bgp.shard.<af>` into a `Vec` (candidates `.0` for AddPath,
best-paths `.1` otherwise), then builds + **encodes** every UPDATE and
ships the bytes — **all on the one main task**. v4-unicast is read back
through the `mirror_v4` replica (the pool doesn't serve reads). The
per-peer Adj-RIB-Out (`peer.adj_out.<af>`) is **always** maintained and
populated *during* the dump (the B.4 fix), so the event-driven withdraw
gate is O(1). `send_ipv4_direct` (`update_group.rs:922`) clusters NLRI
per shared attr-set; the encoded bytes queue on an **unbounded**
`packet_tx`, drained by the writer task (TCP backpressure only there).
Each family ends with an unconditional `send_eor_<af>`.

**Implications.** zebra-rs is the only one of the three with **no
inter-peer dump parallelism** — every new peer's feed competes with every
other peer *and* with steady-state ingest on the single main task, and it
runs the expensive encode there too, with no mid-dump yield. BIRD and
GoBGP both get per-peer concurrency for free from their loop/goroutine
model (each still one-route-at-a-time per peer). The plan's A2
`DumpV4`-to-shards is a **different, orthogonal** axis — *intra*-peer
parallelism by prefix shard — that **neither** reference attempts; the
two are complementary. Two cheaper interim borrows fall out: BIRD's
**resumable, cooperatively-yielding cursor** (don't hold the main task
for a whole RR-scale dump) and a **bounded**-egress backpressure story
(BIRD pauses/resumes on socket-writable; zebra-rs and GoBGP both let an
unbounded queue grow under a slow peer). The always-on Adj-RIB-Out is
zebra-rs's deliberate outlier — heavier memory per peer, but an O(1)
withdraw gate the others re-derive or skip.

## Takeaways for zebra-rs

1. **Two mature stacks independently shard the RIB by prefix hash** —
   strong validation of the direction. zebra-rs is the **shared-nothing**
   variant (no lock / cache-coherency tax), which is why RouteBatch +
   mimalloc put convergence *below* the serial baseline — a lock-based
   design rarely beats its own baseline.

2. **Both parallelize egress — but draw the line differently, and this
   matters for Phase E.** BIRD runs the *export filter itself* on each
   consumer loop (egress policy is parallel). GoBGP runs export *policy*
   serially on the producer and parallelizes only the per-peer encode +
   write. zebra-rs today is closest to "serial fan-out" (the reduce);
   **Phase E.1** already lifts out-policy to a cost-gated parallel
   precompute (the BIRD line), and **Phase E.2**'s update-worker threads
   are the convergence of both references — BIRD's per-consumer
   filter+encode loop, fed like GoBGP's per-peer `outgoingCh`.

3. **BIRD's RCU attribute cache / netindex is the reference for the
   cross-shard interning question.** zebra-rs currently **duplicates** the
   intern store per shard (shard-owned, simple, no sharing). At large N
   the choice is duplicate-per-shard (memory) vs one shared store behind
   RCU/lockfree (BIRD's choice) — revisit if intern memory becomes the
   ceiling.

4. **Each design picks a different serialization point.** BIRD serializes
   best-path per table (and parallelizes across tables); GoBGP serializes
   per prefix (bucket); zebra-rs serializes nothing on the ingest hot
   path (owned shards) and pushes the remaining serial work to the main
   reduce — which is precisely why Phase E (egress) is the next frontier.

5. **The session-up *sync* path is a distinct axis — and zebra-rs's
   weakest (see "The sync path" above).** Steady-state aside, BIRD and
   GoBGP both get *inter-peer* dump parallelism for free from their
   loop / goroutine model, while zebra-rs serializes every new peer's
   feed — and its encode — on the single main task. The A2
   `DumpV4`-to-shards plan adds the *orthogonal* *intra-peer* axis that
   neither reference attempts. BIRD's resumable, cooperatively-yielding
   cursor and a bounded socket-backpressure egress are the two cheap
   interim borrows worth taking even before A2.
