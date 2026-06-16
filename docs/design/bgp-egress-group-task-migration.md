# BGP egress group-task migration (per-peer PET → per-update-group task)

Status: **design / migration plan** (no code). Successor to
`bgp-peer-egress-task.md` (the per-peer egress task, shipped, env/config-gated)
and `bgp-egress-journal.md` (the P1/P2 substrate under it). This memo plans the
convergence both of those gestured at: re-key the egress *task* from **per
peer** (N tasks) to **per `UpdateGroupSig`** (M tasks, M ≤ N), so the egress
task count is the number of update groups, not the number of peers.

## 1. Goal

One persistent **group egress task** per update group, owning the group's
coalescing cache + adj-out + the encode, that builds + out-policy-processes +
encodes each prefix **once** and fans the resulting bytes to every member
peer's writer. This is strictly better than both current egress models:

| | coalesce encode? | off main / parallel? | task count |
|---|---|---|---|
| update-group (gate-off, FRR) | **yes** (per-group cache) | encode on a *transient* `spawn_blocking` per flush; **bucketing on main** | 0 (passive struct) |
| per-peer PET (gate-on, GoBGP) | no (re-encodes per peer) | **yes** (persistent per-peer task) | **N** (peers) |
| **group task (target)** | **yes** | **yes** (persistent per-group task) | **M** (groups) |

At route-reflector scale — 2000 clients sharing one outbound policy — this is
**1 task, 1 encode** rather than 2000 PET tasks each re-encoding, or one
main-thread bucketing loop. It is §12-P1 ("group-affinity update-workers") of
`bgp-rib-sharding-plan.md`; the per-shard journal (P1 substrate) and bounded
channels (P2) ride on top later (§7).

## 2. What already exists — leverage, do not rebuild

The update-group infrastructure is most of the target already; it is just
*passive* (a struct the main reduce flushes) rather than a *task*.

- **`UpdateGroupSig`** (`update_group.rs:120`) — the complete egress identity:
  `peer_type`, `reflector_client`, `local_as`, **`local_addr`**,
  `policy_out_name`, `prefix_set_out_name`, `as_override_target`,
  `remove_private_as`, `local_as_substitute`, and the negotiated wire caps.
  This is the **task key**. Critically `local_addr` is *in the sig*, so
  next-hop-self already shards peers into different groups — members of one
  group share a next-hop, so the encode is genuinely shareable (the concern
  from the journal memo §3.2 is already handled).
- **`UpdateGroup.members: BTreeSet<usize>`** (`update_group.rs:203`) — the fan
  set, maintained by `membership_enroll`/`membership_withdraw`
  (`peer_map.rs:152/179`) and `peer.update_group_id` (`peer.rs:878`). The
  group task's member set *is* this set.
- **`build_flush_job_ipv4` / `FlushJob`** (`update_group.rs:834`) — the
  encode-once **canonical-member transform** + per-member replication that
  already runs on `spawn_blocking` and pushes bytes onto members' writer
  channels. The group task makes this **persistent and delta-fed** instead of
  rebuilt-and-discarded per flush.
- **`peer.adj_out: AdjRib<Out>`** (`peer.rs:818`) — per-peer sent-state; the
  deferred-withdraw guard reads it (`update_group.rs:912`). The migration keeps
  it per-peer first and consolidates to per-group later (§6.1).
- **The PET task machinery** (`peer_egress.rs`) — `EgressDeltaV4`
  {`Advertise`,`RecordAdjOut`,`Withdraw`,`Refresh`,`DumpAdjOut`}, the `Engine`
  (build → out-policy → intern → adj_out dedup → send), abort-on-drop. This is
  re-keyed from peer to group: a PET is the **M=1** degenerate case of a group
  task.

So the migration is *not* a rewrite — it is "give the update group a
persistent task, feed it the reduce's deltas, and make the PET's `Engine` the
group's encoder."

## 3. Target architecture

```
   shard pool (ingress, by prefix)
        │  best-path delta  →  reduce (main): NHT + FIB
        │                         │  one delta PER GROUP (not per peer)
        ▼                         ▼
   GroupEgressTask  (one per UpdateGroupId)
   • ctx: SyncCtx built from the group's sig (shared egress identity)
   • owns the coalescing cache + adj_out + attr interner
   • build + out-policy + encode ONCE
        │  Arc<EncodedUpdate>  (fan to members — cheap, no re-encode)
        ├───────────────┬───────────────┐
        ▼               ▼               ▼
   member p1.tx     member p2.tx  …  member pK.tx     ← per-peer writer (socket)
```

The group task's `SyncCtx` is derived from the **sig**, not a peer — every
member shares it by construction. Members differ only in their *current
`packet_tx`* (the socket), which the task tracks per member and fans the shared
bytes to. The per-connection writer (per peer) is unchanged.

## 4. The two real forks (decide before Phase 1)

1. **adj-out ownership — per-peer (keep) vs per-group (consolidate).** Members
   of a group are sent identical routes, so one **per-group** adj_out is
   correct and saves memory (M copies, not N — the FRR subgroup model). But it
   ripples: the deferred-withdraw guard, `show … advertised-routes`, and the
   "peer leaves the group" catch-up all read per-peer adj_out today.
   **Decision: keep per-peer adj_out through Phase 4** (the group task updates
   each member's `peer.adj_out`), consolidate to per-group in Phase 6.1 once
   the task path is proven.
2. **Delta source — main fans directly (first cut) vs per-shard journal (P1
   full).** **Decision: main reduce fans one delta per group directly** (the
   current PET fan, re-keyed), exactly as today. Swap to the `lfjour` journal
   (`bgp-egress-journal.md`) only after the group task is the default — it is a
   transport optimization, orthogonal to the per-group re-keying.

## 5. Phased migration (env-gated, parity-checked vs BOTH current models)

Introduce a gate (`ZEBRA_BGP_EGRESS_GROUP_TASK`, default off) so gate-off
(update-group flush) and the existing PET gate stay byte-identical during
bring-up. Each phase is gate-on-only and BDD-parity-checked against the
gate-off update-group output (same coalesced bytes) and the PET (same routes).

- **Phase 0 — group-task shell + membership wiring (idle).** Spawn a
  `GroupEgressTask` when an `UpdateGroup` is created, drop it when the group
  empties. Wire `membership_enroll`/`withdraw` to push member add/remove (with
  the member's current `packet_tx`) to the task. No egress routed yet — pure
  lifecycle parity (groups + members track the gate-off machinery exactly).
- **Phase 1 — advertise through the group task.** The reduce fans **one**
  best-path delta per group (keyed by `peer.update_group_id`, deduped across
  members) instead of per peer. The task builds via the sig's `SyncCtx`,
  encodes once (reusing the `FlushJob` canonical transform), fans the `Arc`
  bytes to each member's `packet_tx`, and updates each member's per-peer
  `adj_out`. `update_groups` bucketing + the transient `spawn_blocking` flush
  are bypassed on the gate-on path.
- **Phase 2 — withdraw + peer-down.** Route-gone and peer-leaves deltas fan to
  the group task; it withdraws from the group cache + each member's adj_out and
  emits one MP_UNREACH fanned to members. Preserve the deferred-withdraw
  ordering the current flush guarantees (`flush_done_ipv4` replay).
- **Phase 3 — membership churn (the hard part, §6.2).** A peer whose sig
  changes (policy / caps / session) moves groups: the existing machinery
  updates `members`; the group task must (a) drop the mover from the old
  task's fan set, (b) add it to the new task's fan set, and (c) **re-sync** it
  — re-dump the new group's adj_out to that one member (the FRR subgroup-move
  cost). Reuse the A2 `DumpV4` shape for the per-member re-dump.
- **Phase 4 — reads.** `show … advertised-routes` reads per-peer adj_out (still
  per-peer through Phase 4, so unchanged); `clear` / soft-out becomes "re-dump
  the group to its members." The group task answers a `DumpAdjOut`-style query
  for observability.
- **Phase 5 — make the group task the egress model.** Flip the gate on by
  default after the full N>1 × many-peer matrix proves byte-parity. Retire the
  per-peer PET (it is the M=1 case of the group task) and the transient
  `spawn_blocking` flush. One egress model.
- **Phase 6 (follow-on, optional).**
  - 6.1 — consolidate adj_out to **per-group** (memory: M copies, FRR subgroup
    model); rework the deferred-withdraw guard + advertised-routes reads.
  - 6.2 — feed the group tasks from the per-shard **journal** (P1 full,
    `bgp-egress-journal.md`) + bounded channels with watermark eviction (P2).

## 6. Risks & hard parts

1. **Membership churn / subgroup move (Phase 3).** The genuinely hard piece —
   the same problem FRR spends real code on. A mover needs per-member catch-up
   (re-dump) so it doesn't miss or double an advertisement. Mitigated by
   keeping adj_out per-peer through Phase 4 (the mover's adj_out follows it) and
   reusing the `DumpV4` re-dump path.
2. **Per-member state that does NOT coalesce.** ORF (peer-pushed outbound
   prefix filter) and per-peer MRAI/pacing break a shared encode. The sig
   already shards on `prefix_set_out_name` (static out prefix-set) but **not**
   on dynamic ORF — so a member with active ORF must either get its own
   single-member group (extend the sig) or a per-member post-filter on the
   shared bytes. Enumerate ORF/pacing/add-path-tx before Phase 1; today's PET
   defers these too.
3. **`packet_tx` swap per member.** Connection collision / reconnect changes a
   peer's socket; the task tracks the *current* `packet_tx` per member (the PET
   already does this for one peer — generalize to the member set). Main pushes
   the swap on each connection change.
4. **Ordering.** One prefix → one shard → one group task preserves per-prefix
   order; the deferred-withdraw replay must move into the task. Across groups,
   independent (no global order required).
5. **Backpressure (P2).** A slow member must not stall the group's other
   members — per-member bounded output queues, and the group's cache/adj_out
   advances independently of any one member's drain. This is more acute than
   for the per-peer PET and is the P2 follow-on (6.2).
6. **Counters / observability.** `UpdateGroupCounters` (messages_formatted /
   replicated, bytes, last_format_us) live on the group today and map cleanly
   onto the task; keep them so `show update-group` is unchanged.

## 7. Relationship to the journal (P1/P2)

This memo is the **per-group re-keying**; `bgp-egress-journal.md` is the
**transport** under it. They compose but are independent: re-key first (main
fans per-group deltas directly — Phases 0–5), then optionally swap the fan for
the journal + watermark (Phase 6.2). Doing the re-keying first is the smaller,
higher-value step and the precondition for the journal to feed *group* workers
rather than per-peer ones.

## 8. Decisions to lock before coding

1. Gate name `ZEBRA_BGP_EGRESS_GROUP_TASK` (+ a future `egress-model` config
   enum unifying off / peer-task / group-task), default off.
2. **adj_out per-peer through Phase 4**, per-group in 6.1.
3. **Main fans per-group deltas directly**; journal is 6.2.
4. **v4-unicast first** (the only pooled family; v6/VPN/LU egress later).
5. Keep gate-off (update-group flush) **and** the per-peer PET until Phase 5
   proves parity; the group task subsumes both.

## 9. Recommendation

Build Phases 0–2 as the first reviewable slice (group-task lifecycle +
advertise + withdraw at gate-on, parity vs gate-off), exactly as the A2 / PET
series were staged. Phase 3 (membership churn) is the gate to correctness at
scale and should land before any default flip. The payoff — egress that
coalesces *and* parallelises, at M tasks not N — is the highest-value remaining
item in the sharding roadmap and the natural retirement of the per-peer/per-
group egress-model fork into one model.
