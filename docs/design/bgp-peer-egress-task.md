# BGP per-peer egress task (A2 ⑥ / the §5.3 "(a′)" path)

Status: **design memo (2026-06-16)** — no code yet. A2 ①–⑤ are done and
live; this is the optional **inter-peer-parallelism** follow-up. There is
**no correctness gap behind it** — it is a pure performance enhancement,
opt-in and env-gated, that can be deferred indefinitely.

Cross-refs: `bgp-sync-a2-scoping.md` §5.3 (the (a)/(a′)/(b) fork) and §6 ⑥;
`bgp-sharding-prior-art.md` (the two-axis model).

## 1. Goal

A2 (①–⑤) parallelized the *intra*-peer session-up dump across shards. The
remaining axis is *inter*-peer: today every per-peer egress operation —
out-policy + attribute build, encode, `adj_out` record, and the withdraw
gate — runs **serially on the main task**. A peer egress task (PET) moves
that per-peer work into a per-peer actor so it runs **off the main loop and
in parallel across peers** — the BIRD per-protocol-birdloop / GoBGP
per-peer-goroutine model, which the prior-art memo flags zebra-rs as
lacking.

Concretely it (a) takes the event-driven build+encode+`adj_out` off main,
(b) removes the §5.3 (a) "report-back serial tail" that caps the DumpV4
first cut at ~4–5×, and (c) is the stepping stone to (b) sharded-`adj_out`.

It composes with A2: the shards parallelize one peer's *build* (intra-peer);
the PETs parallelize *record + encode + withdraws across peers* (inter-peer)
— both axes at once.

## 2. The fork it must resolve: `adj_out` (per-peer) vs `update_groups` (cross-peer)

`adj_out` is per-peer, so it moves cleanly into a per-peer task. But the
event-driven egress today runs through **`update_groups`** — the
*cross-peer* coalescing cache (`bgp/update_group.rs`): one group buckets
many peers' identical adverts by attribute, formats **once** on a canonical
member, and replicates the bytes to every member (the FRR update-group
model). A group **spans peers**, so it cannot be owned by any one peer's
task. The withdraw gate touches **both** (`route.rs:2937/3165-3167`:
`adj_out.{contains_key,remove}` *and* `withdraw_ipv4_deferrable(update_groups,…)`
in one breath). So "move `adj_out` to a per-peer task" is not a mechanical
migration — it forces a decision about where coalescing lives.

**Decision (locked): the PET path does not use `update_groups`.** Each PET
encodes its own egress with **per-peer attribute bucketing** (one MP_REACH
UPDATE per attr-set *to its peer*), but **no cross-peer replication** — the
GoBGP per-goroutine model. This **reuses A2's machinery directly**: the PET
builds via `SyncCtx` (the `&Peer`-free egress snapshot, Phase 0) and sends
via `send_ipv4_direct` (the per-peer bucket+encode+send primitive, already
`&SyncCtx`-based). So ⑥ is the event-driven twin of the DumpV4 send path —
not a new encoder.

**Coexistence = the env-gate, not interleaving.** The two egress models are
*alternatives*:

| | gate **off** (default) | gate **on** (opt-in) |
|---|---|---|
| `adj_out` | on `Peer` (main) | in the PET |
| coalescing | `update_groups` (format-once-replicate) | none — per-peer parallel encode |
| wins when | many peers with **identical** egress (route-reflector) | many **diverse** peers + many cores |
| model | FRR update-group | GoBGP per-peer goroutine |

`update_groups` stays exactly as today on the gate-off path; nothing about
it changes. The operator picks the model that fits their peer topology. **We
do not retire `update_groups`** — both models are first-class.

> Tradeoff to state plainly: gate-on **loses cross-peer coalescing**. A
> group of M identical peers formats M times (once per PET, in parallel)
> instead of once-then-replicate. For a route-reflector with hundreds of
> identical clients, keep the gate **off**. ⑥ is for the many-diverse-peers
> edge, not the RR core.

## 3. The peer egress task (PET)

Spawned per peer at Established (gate-on), torn down on session drop. The
existing per-peer **writer** task (drains `packet_tx` → socket, publishes
the Tier-1b gauge) is the natural seed — the PET is that task grown a brain.

**Owns:** `adj_out` (v4 first), the socket writer, the Tier-1b `egress_depth`
gauge, and a `SyncCtx` snapshot (refreshed by main on policy/config change,
the same way `PolicyReplace` refreshes shard policy).

**Inputs (one `select!`):**
- `main → PET` egress deltas: advertise (`prefix` + best `rib`) / withdraw
  (`prefix` gone) for *this* peer.
- `packet_tx → socket`: drain bytes (the writer role) — both the PET's own
  encoded UPDATEs and shard DumpV4 bytes.

**Per delta:**
- *advertise:* build via `SyncCtx` + out-policy → `adj_out.add` → encode
  (per-peer bucket, `send_ipv4_direct`) → enqueue on `packet_tx`.
- *withdraw:* `adj_out.contains_key`? → `adj_out.remove` → encode withdraw →
  enqueue.

## 4. The withdraw gate

Today main, on a route change, consults each peer's `adj_out` and withdraws.
Gate-on, `adj_out` has moved, so **main fans the route-gone delta to every
established PET** (it can no longer know which peers held the prefix); each
PET checks its *own* `adj_out` and withdraws only if present. This is the
GoBGP model: main sequences, peers decide. Cost: N fan-out messages per
route change, most no-ops — but cheap and parallel. (The event-driven
*advertise* already fans out to all group members on main today; ⑥ moves
that fan-out's work into the PETs.)

## 5. Ordering — the one real correctness subtlety

Per-prefix order (advertise-then-withdraw for one prefix) must be preserved.
With a single `main → PET` channel (FIFO) it is, trivially. The hazard is
**two sources into one PET**: the DumpV4 ③ `adj_out` deltas (from the
shards) vs the event-driven deltas (from main) racing a dump-add against an
event-withdraw of the same prefix at session-up.

Two ways to resolve it, and they set the phasing:
- **(i) main sequences** — main forwards *both* the dump ③ deltas and the
  event deltas to the PET on one ordered channel. Trivially correct, but
  main still touches every dump delta (a forward ≈ the insert it replaces),
  so it **does not remove the ③ serial tail** — it only moves `adj_out` +
  encode off main.
- **(ii) shards-direct + PET barrier** — the shards send ③ deltas straight
  to the PET (off main, *removing the tail*); the PET runs a "dumping" state
  that applies dump deltas and **buffers** event deltas until main signals
  the DumpV4 barrier complete, then drains them. Removes the tail and
  preserves order (dump fully applied before events), at the cost of a
  bounded session-up event buffer.

**Decision: (i) first (correct, simple), (ii) as the tail-removal
optimization later.** The early PET wins are the parallel build/encode/
`adj_out` across peers; the ③ tail removal is a follow-on.

## 6. Phased delivery (each phase env-gated, BDD-parity-checked vs gate-off)

- **Phase 0 — PET shell.** Grow the writer task into the PET actor (gate-on):
  same writer behaviour, plus an idle `main → PET` delta channel and the
  `SyncCtx` snapshot plumbing. No `adj_out` move yet — pure lifecycle
  refactor (spawn/teardown parity), zero behaviour change.
- **Phase 1 — event-driven advertise in the PET.** Move `adj_out` into the
  PET; route the event-driven advertise through it (main sends the
  best-path delta; PET builds via `SyncCtx` + `send_ipv4_direct` + records
  `adj_out`). The bulk of the 54 `route.rs` `adj_out` sites collapse to "send
  a delta." `update_groups` is bypassed on the gate-on path.
- **Phase 2 — withdraw gate in the PET.** Main fans route-gone deltas to the
  PETs; each checks its `adj_out` and withdraws (§4).
- **Phase 3 — DumpV4 ③ into the PET.** Forward the dump `adj_out` deltas to
  the PET (ordering option (i)). Optionally then (ii) shards-direct +
  barrier-buffer to remove the serial tail.
- **Phase 4 — reads.** `show … received-routes` (the §⑤ gather already
  scatters to shards for adj-*in*; adj-*out* reads — `advertised-routes`,
  the withdraw-gate-equivalent shows — now gather from the PETs) and `clear`/
  soft-out re-advertise as a "re-dump to this PET."

## 7. Risks & open questions

- **Coalescing loss (§2)** — the headline tradeoff; gate-off remains for RR.
- **Fan-out cost (§4)** — N messages per route change; quantify before
  judging it cheap on a churny RIB with many peers.
- **Ordering (§5)** — the dump-vs-event race; option (i) first.
- **`SyncCtx` freshness** — every policy/config change that affects egress
  must push a fresh `SyncCtx` to the PET (a `PolicyReplace`-style refresh);
  a missed refresh silently advertises stale attrs. Enumerate the inputs
  (out-policy, local-as, caps, next-hop-self, …) — they are exactly the
  `UpdateGroupSig` fields.
- **v6 / LU / VPN** — v4 first; the other families' `adj_out` move later
  (same shape, more `AdjRib` tables).
- **Relationship to (b)** — (a′) is per-peer; (b) is per-prefix
  (each shard owns `adj_out` for its slice, full ~N×). (a′) is simpler and
  precedes (b); they are different axes, not competing first cuts.

## 8. Decisions

**Locked:**
1. PET path **drops `update_groups`**; per-peer encode via `SyncCtx` +
   `send_ipv4_direct` (GoBGP model). `update_groups` stays as the gate-off
   default (FRR model). Both first-class.
2. **Env-gated**, default off; the two egress models are alternatives, not
   interleaved.
3. **v4-unicast first.**
4. Ordering: **main-sequences (i) first**, shards-direct tail-removal (ii)
   later.
5. The **writer task is the PET seed**; Phase 0 is a pure lifecycle refactor.

**Open:**
- Global vs per-peer gate (start global).
- The fan-out cost verdict (§4) — measure on a many-peer churny RIB.
- Whether `advertised-routes`/`clear`/soft-out reads gather from PETs or the
  PET exposes a snapshot (Phase 4 detail).

## 9. Recommendation

Build only if the inter-peer axis is wanted — A2's intra-peer win stands on
its own. If pursued, **Phase 0 + Phase 1** is the smallest reviewable slice
that proves the model (event-driven advertise off main, gate-on parity vs
gate-off) before committing to the withdraw-gate and dump migrations. Treat
it as its own PR series, exactly as A2 was.

## 10. Implementation findings (2026-06-16 — from starting Phase 0)

Reading the actual egress code surfaced two things §3–§6 got wrong; both
change the Phase 0/1 shape, so they are recorded before any code lands.

**(F1) The PET is *not* the writer grown up — it's a new per-peer task that
*feeds* `packet_tx`.** The writer (`peer_start_writer`) is **per-connection**
— spawned at all three connection sites, and collision keeps *two* live at
once. `adj_out` is **per-peer**. So the PET is a separate **per-peer** actor
that builds + encodes and pushes bytes onto the *current* connection's
`packet_tx`; the per-connection writer drains it to the socket, unchanged.
The PET must track the current `packet_tx` (main pushes it on each
connection swap / collision resolution). This is cleaner (the PET never
touches the socket or reconnects) but corrects §3's "writer is the seed."

**(F2) `adj_out` is all-or-nothing, so the per-path phases (advertise /
withdraw / dump / show) do NOT produce shippable intermediate states.** If
Phase 1 moves `adj_out` into the PET for the *advertise* path only, the
still-on-main withdraw gate, DumpV4 ③ record, and `show advertised-routes`
read the now-empty main `adj_out` → **withdraws leak and shows go blank at
gate-on**. So gate-on is only parity-correct once advertise **and** withdraw
**and** dump-③ **and** the reads all move together — i.e. the *whole v4
egress* in one slice, not four.

**Two viable first slices (this is the decision to confirm):**
- **(a) report-back — `adj_out` stays on main.** The PET does the expensive
  work (out-policy build + encode + send) and reports `(nlri, post-policy
  attr)` back; main records `adj_out`. **Incrementally correct** — withdraw
  gate / dump / show are untouched (they keep reading main's `adj_out`).
  Moves the ~75%-CPU out-policy build off main (the headline win). Costs: a
  `main → PET → main` round-trip, and the pre-send **dedup is lost** (the
  PET sends before main records, so a no-op re-advertise re-sends — correct
  routes, redundant UPDATEs, *not* byte-parity). This is the natural
  extension of the §5.3 "(a) first, then (a′)" progression.
- **(a′) full v4 migration — `adj_out` in the PET.** advertise + withdraw +
  dump-③ + reads all move in one (large, ~54-site) slice. Byte-parity-
  capable and the memo's end-state, but big and genuinely all-or-nothing.

**Recommendation: (a) report-back for the first slice.** It sidesteps the
all-or-nothing trap, stays correct at every step, delivers the build-off-main
win, and keeps the slice reviewable; migrate to (a′) later if byte-parity +
the ③ tail-removal are wanted. **Phase 0** (the PET shell) and the channel
shapes differ between (a) and (a′), so the approach must be picked before
Phase 0 code — which is why this is a checkpoint, not a commit.
