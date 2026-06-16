# BGP egress journal — P1 + P2 under the per-peer egress task (PET)

Status: **design proposal** (no code). Successor planning artifact to
`bgp-peer-egress-task.md` (the PET, A2 ⑥, built + live at gate-on) and to
`bgp-rib-sharding-plan.md` §12 P1/P2 (which were written for the
**update-group / gate-off** world). This memo re-derives P1 and P2 for the
**gate-on (`ZEBRA_BGP_PEER_TASK=1`)** world and shows that there they
collapse into a single substrate: a shared, GC'd **egress journal** that the
PETs **cursor over** instead of being **pushed** unbounded per-peer deltas.

## Decisions (proposed — to lock before any code)

1. **One journal, appended by main *post-NHT*** (not per-shard bypassing
   main). NHT-gating is main-owned; a true per-shard journal needs shard-side
   NHT and is deferred (§3.2). Main's per-change cost drops from **O(peers)**
   (the fan loop) to **O(1)** (one append) regardless.
2. **Journal entry carries the data** — `(seq, prefix, Option<Arc<BgpRib>>)`,
   `None` = withdraw. No separate Loc-RIB snapshot to read; attrs are already
   interned (`Arc<BgpAttr>`), so an entry is two pointers. The PET applies its
   **own** egress policy to the shared Loc-RIB best-path (§3.3).
3. **Bounded by watermark + overrun→resync**, not just "GC to slowest
   cursor." A PET that lags past the watermark is **evicted** and re-syncs via
   the existing `DumpV4` path, so one stuck peer can never pin the journal
   (§5).
4. **Env-gated, parity-checked, v4-unicast first** — same discipline as A2 and
   the PET. The journal is only the *transport* for the PET deltas; gate-off
   (update-groups) is untouched.
5. **This memo is P1 + P2 only.** It does **not** restore encode coalescing
   (1000 same-policy peers still encode 1000×). That is the group-task
   convergence (§8) — and it requires this journal as its substrate, so it is
   deliberately sequenced *after*.

## 1. Goal & relationship to P1/P2

Under gate-on the PET already moved the egress build (out-policy + attr
transform + encode + `adj_out`) **off the main thread and into per-peer tasks
running in parallel** — so the original P1 goal ("get egress off the single
reduce thread") is largely **met**. What gate-on left behind are two narrower
defects, one per axis:

- **P1 residual** — the main reduce still runs a fan-out loop,
  `fan_advertise_to_pets` (`route.rs:3048`), that does **one channel send per
  established peer per route change** (`established_plain_idents`,
  `route.rs:3050`). O(peers) serial work on main, every change.
- **P2 (worse than gate-off)** — each PET owns an **unbounded** inbox
  (`mpsc::unbounded_channel`, `peer_egress.rs:99`). 2000 peers ⇒ 2000 unbounded
  queues, and because nothing coalesces before the send, a flapping prefix
  enqueues one delta *per flap* — the backlog grows with **churn**, not RIB
  size. (Update-groups bound it to RIB size via the per-group cache.)

Both point at the same fix: stop **pushing** per-change deltas into per-peer
unbounded channels; instead publish each change **once** to a shared,
bounded, GC'd log and let each PET **pull** at its own pace. That is the
journal.

## 2. The defect precisely (gate-on data flow today)

```
shard THREADS ──ShardOut──► MAIN reduce (route_apply_bestpath_v4_batch)
 (own v4 Loc-RIB)             ├─ reduce_bestpath_v4_nht_fib: NHT + FIB   (serial, main-owned)
                             ├─ mirror_v4_delta: write bgp.shard.v4      (B.4 read replica)
                             └─ fan_advertise_to_pets:                   ◄── P1: O(peers) on main
                                  for ident in established_plain_idents:
                                      peer.pet.delta_tx.send(Advertise|Withdraw)  ◄── P2: unbounded, per-peer, churn-sized
                                          ↓
                                    PET (per peer): build + out-policy + intern + adj_out + send_ipv4_direct
                                          ↓ packet_tx ► per-conn writer ► socket
```

The two ◄── lines are the whole problem. NHT/FIB and the B.4 mirror are
fine where they are (main-owned, O(1) per change).

## 3. The design

### 3.1 Three pieces

- **`EgressJournalV4`** — an append-only log of best-path changes, shared
  `Arc<EgressJournalV4>`, lock-free for one producer (main) and many consumers
  (PETs). Conceptually:

  ```
  struct JournalEntry { seq: u64, prefix: Ipv4Net, best: Option<Arc<BgpRib>> }  // None = withdraw
  struct EgressJournalV4 {
      entries: <append-only ring / segmented vec, atomically published>,
      head:    AtomicU64,                 // next seq
      tail:    AtomicU64,                 // oldest live seq (GC frontier)
      // per-prefix "latest seq" index for skip-on-read coalescing (§4)
  }
  ```

- **A per-PET cursor** — `cursor: u64` (the next seq this PET will read) plus
  the PET's existing `Engine { adj_out, attr_store, ctx, add_path }`
  (`peer_egress.rs:119`). The cursor **replaces** `delta_rx`.

- **A bounded wake signal** — a capacity-1, coalescing notify per PET (a
  `tokio::sync::Notify`, or a `watch`), so the PET sleeps until there is new
  journal data and then drains via its cursor. This channel never backs up: at
  most one pending tick, no data rides it.

### 3.2 Who appends — main, post-NHT (and the per-shard tension)

§12-P1 says "per-shard journal, **bypassing main**." We deliberately **route
through main** in the first cut, because **advertisement is NHT-gated** and
NHT is main-owned (`reduce_bestpath_v4_nht_fib`, `route.rs:2830`): a best-path
with an unresolved next-hop must **not** be advertised until NHT resolves. So
the publish point is *after* NHT on main:

```
main reduce, per delta:  NHT-gate ─► FIB ─► mirror_v4_delta ─► journal.append(prefix, best)
```

Main's per-change work is now **O(1)** (bump `head`, publish one entry) instead
of **O(peers)** (the fan loop) — the P1 win — while NHT correctness stays
where it already lives. A *true* per-shard journal that bypasses main entirely
requires moving NHT-gating into the shards (or accepting advertise-before-NHT
+ retract); that is a larger refactor, recorded as the deeper variant, not the
first cut. One journal, totally ordered by `seq`, is also simpler for ordering
(§7) than N per-shard journals a PET must merge.

Note the journal and the **B.4 read-replica mirror** (`bgp.shard.v4`,
`mirror_v4_delta` `route.rs:2811`) are siblings: the mirror is the *queryable
current state* (for `show` / `DumpV4`), the journal is the *change stream*
(for PET consumption). They are fed from the same post-NHT delta and could
share storage; keep them separate structurally at first.

### 3.3 The PET as a cursor consumer

The PET loop changes from "await a pushed delta" to "on wake, advance the
cursor":

```rust
// replaces `while let Some(delta) = delta_rx.recv().await { engine.handle(delta) }`
loop {
    wake.notified().await;
    while self.cursor < journal.head() {
        match journal.read(self.cursor) {            // Arc<BgpRib> or withdraw
            Live { prefix, best: Some(rib) } => engine.advertise(prefix, rib),
            Live { prefix, best: None }      => engine.withdraw(prefix, 0),
            Superseded                        => {}   // skip — a newer seq for this prefix exists (§4)
            Overrun                           => { resync_via_dump(); }   // §5
        }
        self.cursor += 1;
    }
}
```

Crucially the journal entry carries the **Loc-RIB best-path** (post-best-path,
**pre-egress-policy**); each PET still runs **its own** `route_update_ipv4` +
`route_apply_policy_out` + intern + `adj_out` + `send_ipv4_direct` (the
existing `Engine::advertise`). So per-peer policy/next-hop-self divergence is
preserved exactly — the journal shares the *notification and the source rib*,
not the encoded bytes. (Sharing the bytes is the group-task, §8.)

### 3.4 Spawn / initial state

A PET reaching Established (`peer.rs:1573`) can't replay the journal from
`seq 0` — it's GC'd. So spawn = **(i)** initial full read via the existing
`DumpV4` path (`ShardMsg::DumpV4`, A2 ⑥ ③ — the shards build + send this
peer's whole current slice) **then (ii)** attach the cursor at the journal
`head` captured at dump time. Steady state is cursor-pull thereafter. This
unifies session-up sync, `show`, and steady-state advertise onto one model —
the dump is just "cursor starts at a snapshot," exactly the A2 ⑥ intent.

## 4. How it delivers P1

- Main's per-change egress cost: **O(peers) → O(1)** (one append vs a send per
  peer). The 1→N fan now happens by N PETs each reading one shared entry **in
  parallel**, off main.
- The expensive build (the 74.8%-of-CPU out-policy walk) was already per-PET
  and parallel under gate-on; the journal doesn't change that, it removes the
  *serial dispatch* in front of it.
- **Skip-on-read coalescing**: the per-prefix "latest seq" index lets a PET
  that wakes after a burst process a flapping prefix **once** (read the latest,
  skip the superseded seqs) instead of N times — work, not just memory, scales
  with *distinct changed prefixes*, not churn count.

## 5. How it delivers P2

- **One shared journal** replaces 2000 unbounded per-peer channels. Memory is
  `head − min(cursor)` entries — the lag of the **slowest** PET — not the sum
  of 2000 independent backlogs.
- **Hard bound via watermark + overrun→resync.** "GC to slowest cursor" alone
  is defeated by one permanently-stuck PET. So: cap the journal at a
  **watermark** W entries; a cursor that falls more than W behind `head` is
  **evicted** (its slot dropped), the journal GCs past it, and that PET is
  flagged **overrun** → it re-syncs from a fresh `DumpV4` snapshot and
  re-attaches at the new `head` (correctness-preserving, bounded-cost
  recovery). Net: journal memory ≤ W entries + transient `DumpV4` buffers for
  re-syncing PETs. A slow peer degrades **itself** (a re-dump), never the
  shared structure.
- Entries are `Arc`-cheap (interned attrs), so W can be generous.

This is BIRD's `lfjour` token/watermark model (the one place §11 says BIRD is
ahead of both zebra-rs and GoBGP) with a GoBGP-friendly *evict-and-resync*
overrun policy instead of producer-side blocking — chosen so one slow peer
never applies backpressure to **main** (which feeds *every* peer).

## 6. Unifications it buys

- **`DumpV4` ③ = cursor-from-snapshot** (§3.4) — session-up sync, `show`, and
  steady-state advertise become one path.
- **Refresh / soft-out** (`soft_out_v4_to_pet`) = "reset this PET's cursor and
  re-dump" — the same resync used for overrun.
- **The group-task on-ramp** (§8) — once consumers *pull from a journal*,
  swapping per-peer cursors for per-`UpdateGroupSig` cursors is a localized
  change; the journal is the precondition either way.

## 7. Ordering & correctness invariants

- **Per-prefix order** holds: one prefix → one shard → one main append seq →
  monotonic in the single journal. Each PET applies prefixes in `seq` order.
- **No global cross-prefix order** is required by BGP; the single journal
  gives it for free anyway.
- **adj_out stays per-PET** and authoritative for *what this peer was sent*;
  the journal never reads or owns it. Withdraw still matches by **prefix** (the
  1f fix), `id` 0 on the wire.
- **Eviction is safe**: an overrun PET re-dumps the full current slice, which
  re-establishes `adj_out` consistency from scratch — strictly correct, just
  costlier than incremental.

## 8. What it deliberately does NOT solve

Encode coalescing. 1000 same-`UpdateGroupSig` PETs still each run the
out-policy walk + encode on the shared rib — the headline PET tradeoff
(`bgp-peer-egress-task.md` §2) is untouched. Recovering it = make the consumer
a task **per `UpdateGroupSig` with 1..N member peers** (the group-task /
"update-group between shard and PET" hybrid). That work *requires* this
journal as its delta source, so it is sequenced **after** and gets its own
memo. Framing: the journal makes the consumer *pull-based and bounded*; the
group-task then makes the consumer *coalesced*.

## 9. Phased delivery (env-gated, parity-checked vs gate-off and vs push-PET)

- **Phase J0 — journal type + unit tests.** `EgressJournalV4` (append, read,
  per-prefix index, GC, watermark/overrun) standalone, no wiring. Pure data
  structure + tests (supersession skip, GC frontier, overrun flag).
- **Phase J1 — main appends, PET pulls (parity).** Replace
  `fan_advertise_to_pets` push + `delta_rx` with `journal.append` + cursor +
  wake. Behaviour identical to push-PET; prove against `@bgp_peer_egress_v4`
  at gate-on. New sub-gate (e.g. `ZEBRA_BGP_EGRESS_JOURNAL`) **under** the PET
  gate so push-PET stays the fallback during bring-up.
- **Phase J2 — overrun→resync.** Watermark eviction + `DumpV4` re-attach; a BDD
  that wedges one peer's drain (slow/blocked socket) and asserts the others
  keep converging and memory stays bounded (the P2 teeth).
- **Phase J3 — fold DumpV4 spawn onto the cursor** (§3.4) and retire any
  now-redundant push path.
- **(later, separate memo) Phase G — group-task** consumer (§8).

Each phase is gate-on-only and leaves gate-off (update-groups) byte-identical.

## 10. Risks & open questions

- **Lock-free SPMC correctness** — one producer (main), many consumers; needs
  careful publish/acquire ordering and an immutable-once-published entry. Start
  with a `Mutex`-guarded segmented log if the lock-free version isn't worth the
  risk at first; the API (append / read-at-cursor / GC) is identical.
- **Watermark W tuning** — too small ⇒ healthy-but-bursty peers needlessly
  re-dump; too large ⇒ weak memory bound. Pick after a slow-peer bench (§12-P2:
  "decide after a fan-out/slow-peer bench, not before").
- **Wake amplification** — a single append must not wake 2000 PETs to each read
  one entry. Batch the notify (wake on a small debounce, like the update-group
  flush self-message) so PETs drain runs of entries per wake.
- **NHT-on-main retained** — the first cut keeps the main append; if the main
  append + NHT ever itself becomes the serial ceiling, that is the trigger for
  the per-shard-journal + shard-side-NHT deeper variant (§3.2), not before.
- **Memory of the B.4 mirror + journal together** — both hold v4 state on main;
  confirm the journal (bounded to W) doesn't materially add to the mirror's
  already-accepted FIB-sized replica.

## 11. Recommendation

Build J0–J2 as a small gate-on-under-gate series **only if** the PET is being
pushed toward production scale (many peers) — at which point the unbounded
per-peer channels (P2) are the first thing that must go, and the journal
delivers P1 (kill the O(peers) main fan) in the same change. If the PET stays a
research/opt-in path, this can wait. Either way it is the **prerequisite** for
the group-task coalescing model, so it is the correct next substrate to build
before any P1-via-group-worker work — it subsumes §12-P1 and §12-P2 for the
gate-on world into one artifact.
