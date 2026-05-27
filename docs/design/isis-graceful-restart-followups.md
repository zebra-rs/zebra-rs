# IS-IS Graceful Restart — follow-ups

Snapshot of remaining IS-IS GR work as of `main` ≈ commit `a246c660`
(PR #946 merged). Helper-side (RFC 5306 §3.2) and restarter-side
(RFC 5306 §3.1) are both shipped end-to-end through one operator-
runnable cycle. This memo captures the deferred slices so a future
session can pick from a known list instead of re-deriving the state
of the world.

Companion docs:
- `isis-graceful-restart-restarter.md` — Phase 5 scoping doc for the
  restarter side. Open questions there were resolved during
  implementation; the Phased plan section is the canonical history of
  what each PR delivered.

Before picking the next item, follow the project's standing guidance:
recommend the smallest meaningful slice with the main tradeoff, let
the user redirect, and ship one branch / one PR at a time.

## What shipped (in order)

Each PR is a self-contained slice; reading their diffs is the fastest
way to learn the file layout. Total ~12 PRs, ~3000 LoC, RFC 5306 helper
+ restarter both functional.

### Helper side (RFC 5306 §3.2)
- **#934** — Restart TLV (211) codec in `crates/isis-packet`.
  Bit-layout per RFC 5306 §3, full encode/decode + dispatcher
  round-trip tests.
- **#935** — Per-adjacency observation (`AdjGrState` on `Neighbor`)
  + `show isis graceful-restart`. Read-only; no behavior change.
- **#936** — Helper preservation + RA reply. RFC §3.2(a)
  hold-timer-refresh suppression on retransmitted RR, RFC §3.2(b)
  RA TLV in outbound IIH, immediate IIH origination on Enter for
  fast acknowledgement.
- **#937** — CSNP+SRM kick on first RR. RFC §3.2(b) helper
  election predicate (P2P always, LAN highest priority among
  non-restarting GR-capable neighbors).
- **#938** — `graceful-restart helper-enabled` config knob
  (default true). Gates the helper-mode behavior cleanly so an
  operator can disable per-instance.

### Restarter side (RFC 5306 §3.1)
- **#939** — Scoping doc (`isis-graceful-restart-restarter.md`).
- **#940** — Checkpoint storage layer
  (`zebra-rs/src/isis/checkpoint.rs`). CBOR via `ciborium`,
  atomic write at `/var/lib/zebra-rs/checkpoint/isis.cbor`,
  `ZEBRA_ISIS_CHECKPOINT_DIR` env override, debug CLI
  `clear isis checkpoint {write,clear}` + `show isis checkpoint`.
- **#941** — Pre-restart staging
  (`clear isis graceful-restart {begin,abort}` + RR TLV in IIH).
  `gr_restarter_enabled` config knob (default false).
- **#942** — `clear isis graceful-restart commit` exit path.
  Writes checkpoint, drains 200ms, dispatches `Message::
  GrRestartExit` which runs `std::process::exit(0)`. Kernel
  routes survive via the already-in-tree `despawn_isis_graceful`
  + `ProtoQuiesce` plumbing.
- **#943** — Restart-aware boot. `Isis::new` calls
  `gr_restart_load_checkpoint`; freshness check (1.5×
  grace_period); restores self-LSPs verbatim into LSDB; arms
  auto-abort safety net.
- **#944** — Exit-success on neighbor-up (minimal 5e-ii).
  Tracks `pending_neighbors: BTreeSet<IsisSysId>` from the
  checkpoint; each NFSM Up trims it; success path on empty
  clears restart, re-originates self-LSPs at seq+1, schedules
  SPF. `Message::SpfCalc` gated on `restarting.is_some()` for
  FIB hold-back.
- **#946** — T1 retransmit + OL bit on exit-failure (5e-ii-b).
  3s `Message::GrT1Tick` driver kicks Hellos while restarting.
  Auto-abort path now sets `Isis.overloaded = true`,
  re-originates self-LSPs with `ol_bits=true`, clears OL after
  30s.

## Validation gaps

**No real interop run.** Everything above is unit-tested + workspace
clippy clean. The FRR interop bench described in each PR is deferred.
Highest-payoff per line.

### Two-node FRR-peer test harness
Boot zebra-rs against a real FRR peer. Verify:
- helper: FRR restart → zebra-rs adjacency stays Up, FRR sees RA
  from us, FRR comes back without flap.
- restarter: zebra-rs commit → FRR-side `show isis neighbor` shows
  helper-mode active, FRR LSDB never sees a MaxSeqAdvance event
  for our LSPs across the cycle.
- exit-failure: kill the FRR peer mid-restart → zebra-rs auto-abort
  fires, FRR (when it comes back) sees our LSPs with `ol_bits=1`
  for ~30s.

Reuse existing BDD scaffolding if possible (`zebra-rs/bdd/` —
excluded from CI but locally runnable).

### Single-router golden-traffic captures
Lock the wire format. One `pcap` per direction × per-TLV-content:
IIH with RR=1, IIH with RA=1+remaining-time+neighbor-sys-id,
self-LSP with OL=1. Fixture-decode tests catch regressions.

## Deferred follow-ups

### SR / auth-replay state in the checkpoint (~150 LoC)
The Phase 5 design doc's Open Question #2 recommended **in**, the
Phase 6 PR shipped them as **deferred**. Pure additive — new fields
on `IsisCheckpoint` + `LevelCheckpoint`, bump
`CHECKPOINT_FORMAT_VERSION` if you want strict reject of old files
(or leave it 1 and tolerate absence via `Option`).

Three pieces to capture:
- **SR-MPLS `local_pool` allocations** — `Isis.local_pool: Option<
  LabelPool>` holds the adj-SID label assignments. Without restoring
  them, post-restart adj-SIDs allocate fresh labels and helpers'
  ILMs point at the wrong values until they re-read our LSPs.
- **ELIB End.X SID allocations** — `Isis.elib: ElibPool` holds the
  SRv6 function bits per adjacency. Same drift story as SR-MPLS but
  on the v6 dataplane.
- **RFC 5310 auth-replay state** — per-key-chain last-Key-ID-used
  per adjacency. Without it, the first few IIH/SNP packets after
  restart may be rejected as replays until the peer's window
  resyncs. Lives in `zebra-rs/src/isis/auth.rs`.

Entry point: extend `IsisCheckpoint::from_instance` and the
restore path in `gr_restart_load_checkpoint`.

### `SIGUSR1` / `SIGRTMIN+N` handler (~50 LoC)
`systemctl reload` triggers the same code path as
`clear isis graceful-restart commit`. Operator convenience for
supervisor-driven rolling upgrades. Mirror whatever OSPF did
(check `zebra-rs/src/ospf/inst.rs`); the dispatch just needs to
land on `Isis::gr_restart_commit()`.

### Neighbor identity pre-population at boot (~80 LoC)
`AdjCheckpoint` is captured but only consumed for the
`pending_neighbors` set membership. Pre-populating
`link.state.nbrs` from `AdjCheckpoint` would let the first IIH
from a known peer skip Down→Init and go straight to Init→Up,
shaving ~hello_interval off recovery time.

Wrinkle: `AdjCheckpoint` stores `ifindex` but kernel ifindex shifts
across reboots can break matching. Add `ifname: String` to
`AdjCheckpoint` first, bump `CHECKPOINT_FORMAT_VERSION` to 2 if
strict. Then match by ifname against the kernel-reported link
table.

### Strict RFC 5306 §3.1 T2/T3 modeling (~200 LoC)
Today's exit-success is keyed off NFSM Up; today's wall-clock
bound is the 1.5×grace_period auto-abort. RFC says T2 per level
should track an "expected LSP set" from the first complete CSNP
received over the interface, and T3 should be reset by helpers'
RA Remaining Time values (min across all helpers).

Only matters if interop bench shows the current "all neighbors Up"
signal misses cases where a peer comes back Up but its LSDB is
still partially stale. Defer until evidence.

Entry points:
- Track per-interface "first CSNP received" + the LSP set it
  reported; trim as PSNPs/LSPs arrive; T2 cancels when empty.
- On IIH receive with RA TLV, update a per-instance T3 value.
- OL-clear delay (currently hardcoded 30s in
  `gr_restart_expire`) should be replaced with "wait for T2 to
  cancel".

### YANG `graceful-restart/drain-time-ms` knob (~30 LoC)
Operator-tunable 200ms drain window in `gr_restart_commit`. Mirror
OSPF's same-name knob in `config.yang`. Useful when tunnel/WAN
paths have RTT > 200ms.

## Known smells — not blocking but worth a sweep

- **`RestartingState.t1_timer` carries `#[allow(dead_code)]`** with
  a comment about why (held for Drop). Same pattern exists
  implicitly on `abort_timer` and `overload_clear_timer` but those
  squeak by because they're assigned twice (literal + later
  reassignment counts as a "use"). Inconsistent — either remove the
  pseudo-uses on the other two or add `#[allow]` to all three.

- **`IsisCheckpoint` stores `IsisLspId` / `IsisSysId` as raw
  `[u8;8]` / `[u8;6]`** because the typed structs have asymmetric
  serde (`Serialize` emits display strings, `Deserialize` expects
  struct shape). Documented in `checkpoint.rs` module doc. Cleanest
  fix is to add `Serialize` impls on the typed structs that match
  the derived `Deserialize`, then store typed in the checkpoint —
  but that touches `crates/isis-packet` and risks downstream JSON
  output drift. Worth it only if/when another consumer hits the
  same issue.

- **`Message` enum has grown 5 GR-specific variants** (GrRestartExit,
  GrRestartAbort, GrNeighborUp, ClearOverload, GrT1Tick). Not a
  problem at 5; if more land for strict-RFC T2/T3, consider a
  `GrMessage` sub-enum to keep the main `Message` Display readable.

- **`gr_restart_commit` re-kicks Hellos even when restart was
  already staged via `begin`**. Harmless but redundant; the 5e-ii-b
  T1 timer already covers the cadence. Could short-circuit.
