# A2 — intra-peer shard-parallel dump (`DumpV4`): scoping

Status: **scoping** (2026-06-15). Companion to
[`bgp-rib-sharding-plan.md`](bgp-rib-sharding-plan.md) §B.4 (which sketched
A2) and the Tier-1a/1b cursor work. This memo turns the sketch into an
actionable design grounded in the current source.

## Decisions (locked 2026-06-15)

The three forks (§5) are settled:
1. **Build-without-`Peer` refactor** — yes; one `&SyncCtx` build called
   from both main and shard (§5.1).
2. **Out-policy** — **(A)**: carry `Arc<OutPolicy>` in `SyncCtx` (§5.2).
   The outbound `PolicyReplace` twin is deferred to Phase E.2.
3. **`adj_out`** — **(a) report-back + chunked recording** first (§5.3),
   then **(a′) per-peer task** as the chosen path to inter-peer
   parallelism (delta channel points at a per-peer egress task instead of
   main; the withdraw gate migrates there too; env-gated, default (a)),
   with sharded `adj_out` **(b)** as the deeper Phase-E.2 end-state.

Delivery: **Phase 0 — DONE (2026-06-16).** The `&SyncCtx` build refactor
landed in two folds: the out-policy fold (`Arc<OutPolicy>` cached on the
peer, rebuilt on resolve) and the egress-sink fold (`packet_tx` +
`egress_depth` + `extended_message`, with `send_ipv4_direct(&SyncCtx)`).
`SyncCtx` is now fully `&Peer`-free — a shard worker can do
build → out-policy → encode → send → Tier-1b-park from an `Arc<SyncCtx>`
alone. Pure refactor; validated by workspace clippy + 1254 unit tests +
the out-policy/sync BDDs.

**The `DumpV4` path (①–④, §6) is DONE and LIVE (2026-06-16).** At N>1 the
v4-unicast session-up dump runs shard-parallel — each shard builds + sends
its own authoritative slice and reports `adj_out` deltas; main barriers
the N acks, records adj_out, and emits EoR. Supersedes the main-loop
cursor (kept at N=1). Validated by the full N>1 shard BDD matrix (88
scenarios). Remaining: ⑤ (`show`/`clear`/soft-out via `DumpV4`) and ⑥
(the (a′) per-peer egress task, §5.3).

## 1. Goal & relationship to Tier 1a/1b

Tier 1a (resumable cursor) + 1b (egress backpressure) made the session-up
dump *yield* and *bounded* — but the per-route build (out-policy walk =
the ~75 %-CPU hot spot, attr rewrite, encode) still runs **serially on
the main task**, reading the B.4 v4 *mirror*. A2 moves that build+encode+
send **into the shard workers**: at N>1 each shard already owns only its
prefix-hash slice of `v4`, so each builds + sends *its own* slice in
parallel, from data it owns — no gather, full locality. One `DumpV4`
backs `sync`, `clear`/soft-out, and (partially) `show`.

- **A2 supersedes Tier 1a for the sharded (N>1) v4 path** — the dump no
  longer runs on main, so main-task chunking is moot there. Tier 1a stays
  as the **N=1** path: `ShardPool` is `None` at N=1 (the synchronous
  `self.shard` is used), so `DumpV4` falls back to today's cursor.
- **A2 reuses Tier 1b** — the per-peer `egress_depth` gauge is `Arc`d
  into the `SyncCtx`; each shard increments on send and parks *its own*
  slice above the watermark. N shards + main all enqueue on the one peer
  `packet_tx` (mpsc — concurrent `Send` senders are safe).
- **A2 retires the B.4 mirror for sync** — the workers serve the dump
  from their authoritative `v4`; main's `self.shard.v4` mirror is then
  only needed by `show` (until `show` is streamed too).

## 2. The `SyncCtx` snapshot

The build reads a fixed set of per-peer/per-session values. A shard has no
`Peer`, so `DumpV4` carries a `SyncCtx`. Grounded field list (source field
→ what uses it):

```
struct SyncCtx {
    // identity / classification
    ident: usize,                       // split-horizon (rib.ident == ident)
    peer_type: PeerType,                // iBGP→iBGP suppress, LOCAL_PREF, ORIGINATOR/CLUSTER, NO_EXPORT
    reflector_client: bool,             // RR-client exception to iBGP→iBGP suppress

    // next-hop / addressing
    local_addr_v4: Option<Ipv4Addr>,    // next-hop-self source (peer.param.local_addr → V4)
    router_id: Ipv4Addr,                // nh fallback, ORIGINATOR_ID, CLUSTER prepend, policy `set next-hop self` anchor
    vpnv4_next_hop_self: bool,          // only if VPNv4 rides this path

    // eBGP AS_PATH transform (fold mode + kept-AS, like UpdateGroupSig)
    local_as: u32,
    remote_as: u32,
    as_override: bool,
    remove_private_as: Option<RemovePrivateAsKey>,   // all / replace_as / keep_as
    local_as_substitute: Option<(u32, bool)>,        // resolved change_local_as() incl. dual-as fallback

    add_path_send: bool,                // nlri.id = rib.local_id
    extended_message: bool,             // max packet size
    enhe_next_hop: Option<Ipv4MpReachNextHop>,   // PRE-COMPOSED on main (folds cap_send/recv, origin, scope_id, InterfaceAddrs)
    llgr_recv: LlgrSet,                 // peer.cap_recv.llgr — gates stale-route advertisement
    rtcv4: Option<Arc<BTreeSet<ExtCommunityValue>>>, // only if VPNv4 rides this path

    // OUT-POLICY — NOT shard-replicated today; the load-bearing gap (§5.2)
    out_policy: Arc<OutPolicy>,         // { prefix_set_out, policy_list_out }, applied by apply_policy_net (pure)

    // side effects — not pure data (§5.3)
    packet_tx: UnboundedSender<BytesMut>, // cloned peer.packet_tx — shard enqueues bytes directly
    egress_depth: Arc<AtomicUsize>,       // Tier-1b gauge (shared)
}
```

Three deliberate moves keep this cheap and correct:
- **ENHE is pre-composed on main** (`is_enhe_v4_negotiated()` +
  `compose_enhe_next_hop(peer, interface_addrs)`), so the shard needs none
  of `cap_*`, `origin`, `scope_id`, or `InterfaceAddrs`.
- **`local_as_substitute` is resolved on main** (`change_local_as()`
  already folds the dual-as fallback), so the shard doesn't see raw
  `config.local_as`.
- **Interning is local** — a shard interns the egress attr in its own
  `BgpShard::attr_store`; an `Arc<BgpAttr>` is valid regardless of which
  store deduped it. The only consequence is the `adj_out` hand-off (§5.3).

## 3. The message protocol

```
ShardMsg::DumpV4 { req_id: u64, ctx: Arc<SyncCtx> }     // broadcast to all N shards
ShardOut::DumpDoneV4 { req_id, shard: usize, sent: usize, adj_out: Vec<(Arc<BgpAttr>, Ipv4Nlri)> }
```

- **Broadcast** via the existing `ShardPool::broadcast(|| ShardMsg::DumpV4 {…})`
  (the exact `PolicyReplace` template). `ctx` is `Arc`d so the per-shard
  clone is cheap. N=1 (`shards == None`) → run the Tier-1a cursor on
  `self.shard` instead.
- **Per shard** (`handle_dump_v4`): iterate *its own* slice
  (`self.v4.1` best-path, or `self.v4.0` candidates when `add_path_send`),
  run the shared build (§5.1) per route, intern locally, enqueue bytes on
  `ctx.packet_tx` (bumping `ctx.egress_depth`, parking above the
  watermark — Tier 1b per shard), and accumulate the `adj_out` deltas.
  On slice-done, emit `DumpDoneV4`.
- **Barrier**: no barrier exists today — build one. `process_shard_result`
  counts `DumpDoneV4` per `req_id` (a small `HashMap<u64, usize>` on
  `Bgp`); on the **N-th** ack it (a) records the gathered `adj_out` deltas
  into `peer.adj_out`, then (b) enqueues EoR on the *same* `packet_tx`.
  Ordering holds: EoR follows every shard's UPDATEs already in the
  channel.

## 4. `DumpV4` unifies sync / clear / show — with a caveat

- **`sync`** (session-up) and **`clear`/soft-out** are pure send paths:
  the shard enqueues to the peer — clean, no gather.
- **`show bgp ipv4`** must return *one* gRPC response, so A2-for-`show`
  still gathers rendered rows back to main (the reserved
  `ShardMsg::Show(DisplayRequest)` already anticipates a per-request
  oneshot reply — reuse that channel). This *also* needs the separate
  **streamed/paginated `show`** follow-up to dodge the 4 MB RPC limit the
  Tier-1 measurement hit. So "one `DumpV4` serves all three" is true for
  the send paths, **partial for `show`** (gather, or feed the streamed
  variant).

## 5. The three design forks

### 5.1 The build-without-`Peer` refactor (mechanical, invasive)

`route_update_ipv4` → `route_apply_policy_out` → `send_ipv4_direct` (and
`ebgp_egress_aspath`) all take `&Peer`/`&BgpTop`. Refactor them to take
`&SyncCtx` and call the **same** function from both main (N=1 / event-
driven) and shard (A2) — one build, no divergence. The field substitutions
are exactly the §2 list. Cost control: `out_policy` rides as `Arc<OutPolicy>`
so building a `SyncCtx` per event-driven advertise is an `Arc` clone, not a
policy copy. Recommend wrapping the peer's out-policy in an `Arc<OutPolicy>`
(mirroring the existing `Arc<InPolicy>`) as the first refactor step.

### 5.2 Out-policy shard-replication — the Phase-0 gap

A shard today has **no** peer's outbound route-map/prefix-list. The only
replicated policy is `BgpShard::in_policy` — *inbound* only, and keyed by
the *source* peer's ident (it answers "what in-filter did the sender
have," not "what out-filter does the target want"). Two ways to close it:
- **(A) carry in `SyncCtx`** (the `Arc<OutPolicy>`): per-dump snapshot,
  consistent for the dump. Sufficient for A2 (the dump). Simplest.
- **(B) outbound `PolicyReplace` twin**: replicate `Arc<OutPolicy>` per
  target peer into each shard, kept current on config change. Needed only
  when **steady-state** egress also moves to shards (Phase E.2).

Recommend **(A) for A2**, **(B) later** with Phase E.2.

### 5.3 `adj_out` across shards — the deep fork

`peer.adj_out: AdjRib<Out>` is per-peer, main-owned, with `Arc::ptr_eq`
dedup against the concurrent event-driven send. A shard can't touch it.
- **(a) report-back** (the §3 design): shard returns `(interned_attr,
  nlri)` deltas; main records them after the barrier. Incremental, but
  gathers ~N rows back to main and re-serializes the `adj_out` inserts
  (~0.1 µs/route → ~0.1 s for 1 M). Since that ≈ the *parallelized* build
  at N≈8, the serial `adj_out` tail caps the win at ~4–5× rather than
  ~N×. Mitigation: record the deltas **chunked** off the main loop (reuse
  the Tier-1a cursor machinery) so the *stall* stays low even though total
  recording is serial.
- **(a′) report-back to a per-peer task** — the inter-peer-parallelism
  upgrade of (a). Each established peer owns a task holding its egress
  state: `adj_out`, the `packet_tx`/writer, the Tier-1b gauge, and the
  withdraw gate. The shards still build + out-policy + encode + send their
  slice in parallel, but the `(interned_attr, nlri)` deltas flow to that
  *peer task* instead of back to main; the peer task reflects them into
  `adj_out` **off the main loop**, and multiple peers' dumps record
  concurrently. This removes the main-loop block that (a)'s report-back
  reintroduces — for a single peer the record is still serial (one task),
  but no longer on main. The **withdraw gate migrates to the peer task**
  too: a route change on main dispatches to the relevant peer tasks, each
  consults its own `adj_out` and emits the withdraw. This is the
  *inter-peer* axis the prior-art memo flags zebra-rs as missing (BIRD's
  per-protocol birdloop, GoBGP's per-peer goroutine), and it composes with
  A2: the shards parallelize the *build* (intra-peer), the peer task
  parallelizes *record + egress + withdraws* (inter-peer) — both axes, the
  BIRD/GoBGP-plus-sharding convergence. Cost: per-peer egress state
  migrates off the main loop (the same restructuring GoBGP's per-peer
  goroutine embodies), but (a′) is *incremental on (a)* — "point the delta
  channel at the peer task, migrate the withdraw gate." Env-gate it (like
  `ZEBRA_BGP_SHARDS`): default (a), opt-in (a′), so the first `DumpV4`
  stays simple and the per-peer model is A/B-able. The peer task is also
  the natural home for the Tier-1b backpressure gauge (it lives with the
  writer).
- **(b) sharded `adj_out`**: each shard owns `adj_out` for its slice; the
  event-driven withdraw gate runs in the shard too. Full ~N× and the
  principled end-state (state lives with the data), but it couples with
  moving steady-state egress into shards (Phase E.2) — a big change.

Recommend **(a) + chunked recording first** (keeps the stall low, build is
~N× parallel, the cheap insert is the only serial tail), then **(a′) the
per-peer task** as the chosen path to inter-peer parallelism (takes the
last per-peer work off the main loop; the natural home for Tier-1b
backpressure), with **(b) sharded `adj_out`** as the deeper Phase-E.2
end-state.

## 6. Phased PR breakdown

- **Phase 0 — prerequisites. ✅ DONE (2026-06-16).** Wrapped the peer
  out-policy in `Arc<OutPolicy>` (cached on the peer, rebuilt on resolve)
  and folded the egress sink (`packet_tx` + `egress_depth` +
  `extended_message`) into `SyncCtx`; the build trio +
  `route_apply_policy_out` + `send_ipv4_direct` all take `&SyncCtx`. Pure
  refactor, fully covered by today's tests/BDDs.
- **① `DumpV4` message + barrier. ✅ DONE (2026-06-16).**
  `ShardMsg::DumpV4 { req_id, Arc<SyncCtx>, params }` +
  `ShardOut::DumpDoneV4` + `DumpBarrierV4` (per-`req_id` ack counter) in
  `process_shard_result`. Shard handler was a stub ack at ①; barrier
  unit-tested.
- **② shard `handle_dump_v4`. ✅ DONE (2026-06-16).** Walks the slice,
  builds (§5.1) + interns locally + buckets by attr + encodes + enqueues
  on `ctx.packet_tx` with the Tier-1b park (the shard is a dedicated
  thread, so it *blocks* rather than yielding like the cursor). Real
  per-shard `sent` count. `DumpParamsV4` carries the peer-derived inputs
  (AddPath, LLGR-capable, ENHE next-hop, watermark).
- **③ `adj_out` record-back. ✅ DONE (2026-06-16).** Each `DumpDoneV4`
  carries the `(nlri, rib)` rows; main records them per-shard (spread
  across the N acks to keep the stall low) and emits EoR on the barrier's
  last ack — every dump UPDATE is queued by then (each shard enqueues its
  slice before acking; the writer channel is FIFO). Rows record as-is (no
  re-intern); the presence-keyed withdraw gate makes the shard-vs-main Arc
  identity at most a duplicate-UPDATE cost, never correctness. *(Finer
  sub-message chunking deferred — per-shard spreading already bounds the
  per-message stall to ~total/N.)*
- **④ wire `route_sync_ipv4` through `DumpV4` at N>1. ✅ DONE (2026-06-16),
  LIVE.** `route_sync` skips its v4-unicast block when `v4_via_pool`; the
  FSM-event handler broadcasts `DumpV4` once the peer reaches Established
  (supersedes the cursor at N>1 — the sync now reads the *authoritative*
  shard slices, not the B.4 mirror). Cursor/legacy kept at N=1. AddPath
  send covered by `@bgp_shard_addpath_v4` (cands slice). First production
  behaviour change; validated by the full N>1 shard BDD matrix (88
  scenarios). The DumpV4 path (①–④) is now live.
- **⑤ wire `show` + `clear`/soft-out** through `DumpV4` (show via the
  gather/oneshot; pair with the streamed-`show` follow-up).
- **⑥ (a′) per-peer egress task** (inter-peer parallelism, §5.3, env-gated
  — default (a)). Spawn a per-peer task owning `adj_out` + `packet_tx`/
  writer + the Tier-1b gauge; point the ③ delta channel at it instead of
  main; migrate the event-driven withdraw gate there (main dispatches
  route changes to the relevant peer tasks). Takes the last per-peer work
  off the main loop. Incremental on ③; precedes (b).

## 7. Risks & open questions

- **Build divergence** — mitigated by the single `&SyncCtx` build (§5.1);
  the Phase-0 pure refactor lands it under existing test coverage *before*
  any sharding behaviour change.
- **Policy consistency** — the `SyncCtx` snapshot must be the peer's
  out-policy *at dump time*; a concurrent policy change mid-dump uses the
  snapshot (consistent), and the event-driven path re-converges after.
  (Matches how `PolicyReplace` handles ingest.)
- **`adj_out` tail** (§5.3) — the report-back caps the first cut at ~4–5×;
  honest, and the chunked recording keeps the *stall* (not the throughput)
  low. Quantify before deciding whether (b) is worth it.
- **VPNv4/RTC/LLGR** — `vpnv4_next_hop_self`, `rtcv4`, `llgr_recv` only
  matter if those rows ride the v4-unicast path; scope A2 to plain
  v4-unicast first and gate the rest.
- **EoR & GR** — unchanged (`send_eor_ipv4_unicast` on main after the
  barrier); ordering preserved by the single `packet_tx`.
- **N=1 parity** — `DumpV4` must be a no-op detour at N=1 (cursor path),
  so existing N=1 behaviour and BDDs are untouched.

## 8. Recommendation

Land **Phase 0 first** (the `Arc<OutPolicy>` + the `&SyncCtx` build
refactor) — it's a pure, fully-covered refactor that de-risks everything
after it, and is independently useful. Then ①–④ deliver A2 for v4-unicast
sync with **report-back `adj_out` + chunked recording** (~4–5× at N≈8,
low stall). Treat **sharded `adj_out` (5.3b)** and the **outbound
`PolicyReplace` twin (5.2B)** as the Phase-E.2 convergence (shards own
steady-state egress too), where they buy the remaining headroom to ~N×.
`show` rides A2 only once the streamed/paginated `show` lands.
