# IS-IS Graceful Restart — restarting-router mode (Phase 5)

Scoping doc for the restarting-router side of IS-IS GR. Helper mode
shipped through Phase 4 on `main` (PRs #934 codec, #935 observation,
#936 helper preservation + RA, #937 CSNP+SRM kick, #938 `graceful-
restart helper-enabled` knob). This document picks up from there.

References:

- **RFC 5306 §3.1** — restarting-router procedures (state machine,
  T1/T2/T3 timer semantics, OL-bit behavior during restart).
- **RFC 5306 §3.4** — "starting router" procedures (fresh boot path
  using `SA=1, RR=0` to suppress neighbor advertisement of the new
  adjacency until DB sync completes).
- **RFC 5306 §3.3** — error / abort conditions and timer ceilings.
- Companion doc: `docs/design/ospf-graceful-restart-restarter.md`
  (locked 2026-05-25; v2 restarter landed via #888 / #900 / #904 /
  #905 / #907 / #908). The IS-IS plan reuses the same checkpoint
  storage philosophy but the protocol shape is materially different.

Per the project's
`[[feedback-confirm-direction-before-sinking-work]]` guidance, **do
not start coding until the decisions in "Open questions" below are
made.** Restarter mode touches process lifecycle and the kernel-route
ownership contract — choices here are hard to unwind once they ship.

## Why this is harder than helper mode

Helper mode was pure receive-side: detect Restart TLV, suppress one
timer, reply with RA. State was in-memory and ephemeral. Restarter
mode is the opposite shape:

1. **State must survive across `exec`.** The IS-IS daemon exits, a
   new process starts, and the helpers around us expect to see our
   LSPs reappear at sequence numbers ≥ what they snapshotted.
   `lsp_generate` today (`zebra-rs/src/isis/lsp.rs:447-451`) starts
   seq at `0x0001` on cold start with no `seq_floor` hint —
   guaranteed to be lower than what helpers hold, which triggers
   the helpers' MaxSeqAdvance path and tears restart down.
2. **Kernel routes must NOT be torn down on exit.** Today
   `despawn_isis` (`zebra-rs/src/config/isis.rs:27`) sends
   `rib::Message::ProtoCleanup`, which withdraws every route the
   protocol owns (`rtype == RibType::Isis`). GR exit needs a
   different lifecycle path — and we already have one:
   `despawn_isis_graceful` (`config/isis.rs:43`) sends
   `ProtoQuiesce` instead. It's `#[allow(dead_code)]` today because
   nothing calls it; wiring is a Phase 5d concern, not new code.
3. **SPF and FIB must be held back during restart.** RFC 5306 §3.1
   forbids the restarter from updating its forwarding tables until
   T2 expires per level. The current `spf_schedule` /
   `apply_spf_result` path has no concept of "compute but don't
   install" — it always installs.
4. **OL bit must flip on if T3 expires before T2 completes.**
   `IsisLspTypes::ol_bits: bool` already exists in
   `crates/isis-packet/src/parser.rs:302`, but no code path sets it
   today. The restarter needs to drive it from a "still
   resynchronizing" runtime flag.
5. **Pre-exit ordering.** The pre-restart IIH+RR burst must reach
   every neighbor *before* the raw socket closes. Helper-mode
   already exits gracefully via the existing shutdown path; the
   restarter needs a drain window — analogous to OSPF's
   `drain-time-ms`.
6. **Choice of "restarting" (full) vs "starting" (lighter).** RFC
   5306 §3.4 defines a second mode for fresh boots — SA=1, RR=0,
   no checkpoint — which delivers weaker forwarding-state
   preservation in exchange for not needing persistent storage. The
   doc lays out both paths; the decision is in "Open questions".

## RFC 5306 §3.1 — what the restarter must do

| Step                              | What                                                                                       |
| --------------------------------- | ------------------------------------------------------------------------------------------ |
| Pre-restart (operator-triggered)  | Originate IIH+RR on every active circuit. (Helpers refresh hold timer once, send RA.)      |
| Pre-restart (state preservation)  | Persist: per-level self-originated LSP (seq + body), per-adjacency neighbor identity, configured priority/MAC for DIS continuity, SR adj-SID label allocations, key-chain auth state. |
| Exit                              | Tear down the daemon without withdrawing kernel routes (`ProtoQuiesce`).                   |
| Restart                           | On startup, detect checkpoint, load it, enter restarting state. Re-acquire kernel link state. Start T1 per interface/level, T2 per level, T3 system-wide (init 65535s). |
| Re-adjacency                      | Send IIH+RR on every restored interface. Helpers respond with RA + their Remaining Time. T3 = min(T3, sum of RA Remaining Times). T1 cancelled per interface on RA-with-CSNP-set received. |
| LSDB resync                       | First CSNP from each helper records expected LSP list; PSNPs and LSP updates trim it. T2 cancelled per level when list empties and all T1s for that level are cancelled. |
| Re-originate own LSPs             | Only after T2 cancels for the level. Use `seq = max(checkpointed, observed) + 1`.          |
| Exit-restart success              | T3 cancels when both T2s cancel. Clear OL bit (if set), update forwarding tables, delete checkpoint, send normal IIH (RR=0). |
| Exit-restart failure / timeout    | T3 expires before T2 completes per level → set OL bit on originated LSPs, flood, resume normal IIH (RR=0). Clear OL when T2 finally cancels. |

## Current state in zebra-rs

| Piece                                                | Status   | Location |
| ---------------------------------------------------- | -------- | -------- |
| `ProtoQuiesce` IS-IS exit path                       | **Present**, no caller | `zebra-rs/src/config/isis.rs:43` (`despawn_isis_graceful`, `#[allow(dead_code)]`) |
| `RibType::Isis` route tagging                        | Present  | `zebra-rs/src/isis/rib.rs` (every `make_rib_entry` writes `rtype: RibType::Isis`) |
| OL bit modeling                                      | Present, never set | `crates/isis-packet/src/parser.rs:302` (`ol_bits: bool` in bitfield); `IsisLspTypes::from(level.digit())` at `lsp.rs:384,555` builds without OL |
| Self-LSP seq persistence                             | Missing  | `lsp.rs:447-451` defaults to `0x0001` on cold start; `seq_floor` is the MaxSeqAdvance recovery hint, not restart persistence |
| Checkpoint storage layer (IS-IS)                     | Missing  | OSPF has `zebra-rs/src/ospf/checkpoint.rs` (CBOR via `ciborium`); IS-IS should mirror |
| Pre-restart IIH+RR originate                         | Missing  | `ifsm::hello_generate` / `hello_p2p_generate` don't carry a Restart TLV with RR=1 |
| `clear isis graceful-restart {begin,commit,abort}` vty + signal | Missing  | no operator-triggered restart entry |
| T1 / T2 / T3 timer scaffolding                       | Missing  | no per-interface T1, no per-level T2, no system T3 on `Isis` instance |
| SPF / RIB hold-back during restart                   | Missing  | `rib::spf_schedule` and `apply_spf_result` always install; no "compute but defer install" mode |
| Restart-aware `Isis::new`                            | Missing  | `inst.rs:444` cold-starts unconditionally |
| `gr_restarter_enabled` config knob                   | Missing  | helper has `gr_helper_enabled` (`config.rs:454`); restarter needs the parallel leaf |

## Phased plan

Sub-slice analogous to OSPF's 5a–5e. Each PR must land green on its
own before the next is queued.

The "5a" prerequisite (ProtoQuiesce variant) is **already in tree**
— `despawn_isis_graceful` exists and `rib::Message::ProtoQuiesce`
is already wired through the RIB. So the IS-IS plan is one PR
shorter than OSPF's; numbering starts at 5b for clarity that the
sequencing maps to OSPF's.

### 5b — Checkpoint storage layer

Pure scaffolding: serde + on-disk store. No protocol behavior.

- `zebra-rs/src/isis/checkpoint.rs` carrying:
  - `IsisCheckpoint` struct with: per-level self-originated LSP
    seq + wire body keyed by `IsisLspId`, per-adjacency identity
    snapshot (sys_id + ifindex + circuit_id + last NfsmState),
    SR adj-SID `local_pool` allocation state, ELIB End.X SID
    allocation state, hostname mapping snapshot, key-chain
    last-Key-ID-used (so post-restart auth replay protection is
    consistent — see "Open questions").
  - Atomic write (`tempfile` → `fsync` → `rename`) under
    `/var/lib/zebra-rs/checkpoint/isis.cbor`. Matches the OSPF
    path; same `StateDirectory=` systemd requirement.
  - Read-only `Isis::load_checkpoint(path)` returns
    `Option<IsisCheckpoint>`. On parse failure or missing file,
    `None` (caller cold-starts).
  - **Not yet wired** into the lifecycle. Debug CLI
    `clear isis checkpoint {write,read,dump}` (the `dump`
    pretty-prints CBOR to JSON for ops inspection — same pattern
    OSPF added).

Why CBOR not TOML: per-LSP wire bytes are 200–1500 octets;
hundreds of LSPs typical; TOML inflates that 2–5× via base64 and
indentation, gains nothing (operators don't hand-edit
checkpoints). `ciborium` is RFC 8949, stable across crate
versions, already a dep via OSPF.

### 5c — Pre-restart IIH+RR originate + restarter config flag

Operator-triggered pre-stage. Still no actual restart; just
exercises the send side of the helper handshake we already decode.

- YANG: add `gr_restarter_enabled` leaf under the existing
  `graceful-restart` container in `config.yang`. Default
  **`false`** until 5d/5e make the full path safe — restarter
  capability without checkpoint + exit wiring would advertise GR
  on the wire while still tearing down routes on every restart,
  which is worse than no GR. (Helper continues to default `true`
  as today.)
- New vty: `clear isis graceful-restart begin [period N]`.
  Handler:
  1. For each Up interface, build IIH containing
     `IsisTlvRestart { flags: RR, remaining_time: None }` and
     send via the existing `hello_send` path. The Phase 1 codec
     and the send path's TLV vector already accept this — only a
     new TLV-build branch in `hello_generate` /
     `hello_p2p_generate` is needed.
  2. Set `Isis.restarting = Some(RestartingState { … })` —
     locks out config changes; LSP refresh timers stop firing
     (we must not re-originate at higher seq during restart, per
     RFC 5306 §3.1).
  3. Start T1 per interface (default 3s) so retransmits fire if
     no RA arrives.
- **No actual exit yet.** This PR shows we can pretend to be
  restarting without breaking the data plane; helpers around us
  enter helper mode (their Phase 3a path) and reply with RA. A
  `clear isis graceful-restart abort` walks the restart back
  (re-originate normal IIH with RR=0, clear `restarting`).

### 5d — Exit + checkpoint write + skip-cleanup

Wires 5b + 5c into the actual exit path.

- `clear isis graceful-restart commit` extends the 5c sequence:
  - Originates IIH+RR (5c).
  - Writes the checkpoint (5b) — per-level LSDB (only self LSPs;
    see "Open questions"), per-adjacency identity, SR/ELIB pool
    state, hostname map, auth-replay state.
  - Sleeps briefly (drain window — 200ms default to match OSPF,
    operator-tunable via YANG) so the IIH+RR reaches the wire
    before the socket closes.
  - Despawns the protocol task with `despawn_isis_graceful`
    (already present) so `ProtoQuiesce` runs instead of
    `ProtoCleanup`. Kernel routes tagged `RibType::Isis` persist.
  - Supervisor (systemd / operator) restarts the process. Out of
    band of this PR — we just provide the clean exit and trust
    the supervisor wraps it.
- Also: `SIGUSR1` (or `SIGRTMIN+N`) feeds the same handler so
  supervisor-driven restarts (`ExecReload=`, rolling upgrades)
  don't need vty round-trips.

### 5e-i — Load checkpoint + skip cold-start

Pick up the checkpoint on the next boot.

- `Isis::new` (`inst.rs:444`) checks for a recent checkpoint
  (within `1.5 × restart_grace_period` per OSPF's pattern). If
  present:
  - Skip the normal cold-start self-LSP origination.
  - Pre-populate per-level LSDB self entries from the checkpoint
    (seq + wire body intact, so re-flooded LSPs match what
    helpers hold).
  - Pre-populate `local_pool` SRLB allocations + ELIB End.X
    allocations from the checkpoint so adj-SID labels remain
    stable across the restart.
  - Pre-populate neighbor entries at their last-known sys_id +
    ifindex + circuit_id, NFSM state `Down` (IIH receive will
    drive them back to Up via the standard path).
  - Set `Isis.restarting = Some(RestartingState { … })` —
    arms T2 per level (default 60s) and T3 system-wide (init
    65535s, then min of helpers' Remaining Times as they reply).
  - Start sending IIH+RR on every restored interface.
- No re-adjacency or LSDB resync logic yet — that's 5e-ii.
- Validation: the boxed-up checkpoint correctly survives a clean
  restart cycle. Helpers around us re-enter helper mode (they
  see our IIH+RR), but we don't yet drive the resync.

### 5e-ii — Drive re-adjacency to exit-restart success/failure

The other half of restart.

- On IIH receive from a checkpointed neighbor that returns RA,
  record their Remaining Time; T3 ← min(T3, sum of helpers' RA).
- On first CSNP received over an interface, record the LSP list
  as "expected" for that level's T2 (RFC 5306 §3.1).
- On each subsequent LSP / PSNP that arrives, trim the expected
  list. When the list empties AND all T1s for that level have
  cancelled, cancel T2 for that level.
- When all T2s have cancelled, compute SPF per level (the
  existing `spf_schedule` path) but do NOT install yet.
- When BOTH levels' SPFs have completed (single-level instances
  trivially satisfy this), install routes (same `rib::Message`
  paths as today) and clear `restarting`. Re-originate self LSPs
  at `seq + 1` (now with `restarting = None`, so refresh timers
  resume). Delete the checkpoint file.
- If T3 expires before all T2s cancel: set the OL bit on the
  next self-LSP origination
  (`IsisLspTypes::new().with_ol_bits(true)`), flood, resume
  normal IIH (RR=0). Continue holding back the FIB until each
  level's T2 finally cancels, then clear OL. Same cleanup
  (`restarting = None`, delete checkpoint).

### 5f (deferred) — "starting" mode (RFC 5306 §3.4)

A second mode worth shipping later — the fresh-boot case using
`SA=1, RR=0`. No checkpoint needed; the starting router asks
neighbors to suppress its inclusion in their LSPs (SA bit) until
DB sync completes, then transitions to normal IIH. Delivers
weaker preservation than full restart (we DO withdraw routes on
exit — the helper-suppress is purely "don't make me a black hole
during boot") but useful for fast cold-boot convergence.

Two independent value adds. Pick up after 5e-ii proves stable;
not in this scoping doc's critical path.

## Open questions (decide BEFORE coding 5b)

These are the calls that need answers — each is load-bearing on
the PR shape.

1. **Full restarter, or "starting" mode only?**
   - Full restarter (path above): preserves FIB across exit;
     requires checkpoint storage, exit wiring, restart-aware boot,
     and re-adjacency state machine. ~4 PRs, ~1500 LoC.
   - Starting-only: ~1 PR. We just send `RR=0, SA=1` on every
     boot; neighbors suppress us in their LSPs until our DB syncs.
     No checkpoint, no FIB preservation. Useful if planned-restart
     downtime is not the operational pain point.
   - Recommendation: full restarter, since the operational ask for
     IS-IS GR is almost always "no traffic loss during a planned
     restart". Starting mode is a value-add but not the headline.
     Confirm before 5b.

2. **What goes in the checkpoint?**
   - Minimum: per-level self-LSPs (seq + body), per-adjacency
     identity (sys_id + ifindex + circuit_id), and
     `restart_started_at` timestamp.
   - Plus: SR `local_pool` allocations + ELIB End.X allocations
     — without these, adj-SID labels would drift across restart,
     silently breaking SR-MPLS / SRv6 forwarding for in-flight
     traffic. **Decide: in or out?** (Recommendation: in — the
     volume is small and the cost of getting it wrong is silent
     traffic loss.)
   - Plus: RFC 5310 generic-crypto auth-replay state (last seen
     Key ID + counter per adjacency). Without this, post-restart
     IIH/SNP may be rejected as replays for the first few seconds
     until peers re-sync. (Recommendation: in. Cheap to persist;
     prevents flap.)
   - Plus: hostname-map snapshot (`Hostname` from `hostname.rs`).
     Used by `show` only; can be re-derived from incoming LSPs.
     (Recommendation: out — re-derive.)

3. **Checkpoint format + path.** CBOR via `ciborium` at
   `/var/lib/zebra-rs/checkpoint/isis.cbor` — same pattern OSPF
   uses. YANG knob `graceful-restart/checkpoint-path` for
   container deployments. **Decide:** ship the YANG knob in 5b
   or wait until an operator asks? (Recommendation: ship it.
   Cheap, mirrors OSPF.)

4. **Operator entry: vty + signal, or RPC?**
   - vty (`clear isis graceful-restart {begin,commit,abort}`) for
     interactive use.
   - `SIGUSR1` (or `SIGRTMIN+N`) for systemd `ExecReload=`.
   - YANG-action / NETCONF RPC: skip — no RPC plumbing exists,
     no operator demand evident in the codebase.

5. **OL bit policy when T3 expires before T2.** RFC 5306 §3.1 says
   the restarter MUST set OL on its newly-originated LSPs in this
   case and clear it when T2 finally cancels. **Decide:** apply
   OL only to fragment 0, or every fragment? (Recommendation:
   fragment 0 only — that's where helpers / neighbors look for the
   per-node attributes. Set OL on every fragment is RFC-compliant
   too but a bit louder than needed.)

6. **Drain window.** OSPF uses 200ms default with a 50–2000ms YANG
   range. Same for IS-IS? (Recommendation: yes — identical
   semantics, no reason to diverge.)

7. **Restart-while-helping.** Can the restarter simultaneously be
   a helper for *other* peers' restarts? RFC 5306 doesn't forbid
   it, and the state is per-adjacency on both sides. **Decide:**
   support in 5e-ii, or defer to a polish PR? (Recommendation:
   defer — the test matrix gets ugly fast and the common case is
   "one router restarts at a time".)

8. **Clock source.** Wall clock (`SystemTime::now`) for the
   checkpoint timestamp + freshness check, same as OSPF.
   Monotonic resets on the event we're trying to span. NTP-
   corrected wall is the only signal that survives reboot.
   (Recommendation: yes, mirror OSPF.)

## Non-goals (explicitly deferred indefinitely)

- **Hot-restart via process exec.** RFC 5306 doesn't require
  exec-in-place; cold restart via the supervisor works. Skip
  unless an operator articulates a benefit beyond what
  drain-window GR already provides.
- **Restart coordination between IS-IS + OSPF + BGP** running in
  the same daemon. Each protocol checkpoints independently; the
  three GR systems don't need to know about each other.
- **L1+L2 instance running in restart while only one level is
  reconverged.** Level-1 and Level-2 are nearly-independent LSDBs
  with separate T2s; the restart is "complete" only when both
  level T2s have cancelled. Single-level instances trivially
  satisfy this. No special case needed.
- **DIS continuity.** RFC 5306 §3.1 explicitly says DIS election
  is NOT preserved across restart — neighbors re-elect normally.
  We don't need to checkpoint or restore DIS state.

## Interactions with neighboring work

- **OSPF restarter (`docs/design/ospf-graceful-restart-restarter.
  md`)** — landed v2 via #888 / #900 / #904 / #905 / #907 / #908.
  Reuses the same `rib::Message::ProtoQuiesce` we already have for
  IS-IS. Checkpoint pattern is the same shape. Worth lifting the
  checkpoint-path YANG knob into a shared model if the IS-IS path
  ends up identical to OSPF's.
- **Authentication (PRs #916–#924)** — RFC 5310 generic-crypto
  state needs to survive restart (see Open Question #2). The
  existing per-key-chain rotation logic lives in
  `zebra-rs/src/isis/auth.rs`; checkpoint just needs to capture
  the last Key ID used per adjacency.
- **TI-LFA / SR-MPLS / SRv6** — `local_pool` and ELIB allocation
  order is the load-bearing piece. Re-deriving labels after
  restart would silently drift the LSP content vs what helpers
  hold, tripping their MaxSeqAdvance recovery. Checkpoint these.

## Estimated PR sizing

| PR     | Subject                                          | Status   | Estimated LoC |
| ------ | ------------------------------------------------ | -------- | ------------- |
| 5a     | `ProtoQuiesce` IS-IS exit path                   | **already in tree** | (0)  |
| 5b     | Checkpoint storage layer + `clear … checkpoint`  | not started | ~450      |
| 5c     | Pre-restart IIH+RR originate + restarter knob    | not started | ~300      |
| 5d     | Wire 5b+5c into actual exit path                 | not started | ~200      |
| 5e-i   | Load checkpoint + skip cold-start                | not started | ~250      |
| 5e-ii  | Drive re-adjacency to exit-restart success       | not started | ~350      |
| 5f     | (deferred) "starting" mode (RFC 5306 §3.4)       | TBD      | ~150         |
| **Total (5b–5e)** | **full restarter**                  | **not started** | **~1550** |

Estimates calibrated against OSPF (~1420 LoC actual for the full
v2 restarter), trimmed for the IS-IS savings: ProtoQuiesce already
exists, OL bit already modeled, no v3 mirror to write (IS-IS is
single-protocol over both AFs). Offset by IS-IS-specific cost: T1
+ T2 + T3 timer scaffolding has no OSPF analogue (OSPF uses a
single grace-period timer).
