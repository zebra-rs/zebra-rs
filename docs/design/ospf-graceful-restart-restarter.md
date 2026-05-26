# OSPF Graceful Restart — restarting-router mode (Phase 5)

Scoping doc for the restarting-router side of OSPF GR — what the
parent `ospf-graceful-restart-plan.md` Phase 5 explicitly deferred.
Helper mode is complete on `main` (v2 + v3: PRs #855, #861, #864,
#867, #869, #873, #875). This document picks up from there.

References:

- RFC 3623 §2 — OSPFv2 restarting-router procedures.
- RFC 5187 §2 — OSPFv3 restarting-router procedures.
- RFC 4811 / 4812 — auxiliary LR-bit signaling for v3.
- RFC 7770 — `gr_capable` capability bit (Router Information LSA).

Per the project's `[[feedback-confirm-direction-before-sinking-work]]`
guidance, **do not start coding until the open questions below are
answered.** Restarter mode touches process lifecycle and the
kernel-route ownership contract — design choices here are hard to
unwind once they ship.

## Why this is hard

Helper mode was a pure receive-side feature: detect a Grace LSA,
suppress one timer, exit on a flood event. The structs were
in-memory and ephemeral. Restarter mode is the opposite shape:

1. **State must survive across `exec`** — the daemon exits, a new
   process starts, and adjacencies must come back to Full with the
   pre-restart LSDB contents matching what the helpers snapshotted.
2. **Kernel routes must NOT be torn down on exit** — but today
   they are, via `rib::Message::ProtoCleanup` from
   `despawn_ospf` (`zebra-rs/src/config/ospf.rs:20`), which
   withdraws every route the protocol owns. A GR exit needs a
   different lifecycle path that drops the protocol task without
   firing `ProtoCleanup`.
3. **Sequence-number continuity** — RFC 3623 §3 requires the
   restarter to re-flood its pre-restart Router-LSA at the same
   `(seq, checksum)` the helper snapshotted, otherwise the helper
   trips its `gr_helper_check_exit` (`inst.rs:1627`) on the
   restarter-LSA mismatch and the restart fails.
4. **Pre-exit ordering** — Grace LSAs must reach every neighbor
   *before* the raw socket closes. The current shutdown path has
   no drain window.

## RFC 3623 §2 / RFC 5187 §2 — what the restarter must do

| Step                              | What                                                                                          |
| --------------------------------- | --------------------------------------------------------------------------------------------- |
| Pre-restart (operator-triggered)  | Originate a Grace LSA on every active interface; flush before exit.                           |
| Pre-restart (state preservation)  | Persist router-id, interface IDs (v3), neighbor adjacency state, self-originated LSA seq numbers + bodies, and the per-area LSDB snapshot needed for the exit-restart consistency check. |
| Exit                              | Tear down the daemon without withdrawing kernel routes.                                       |
| Restart                           | On startup, detect the checkpoint, load it, enter restarting state. Re-acquire kernel link state. |
| Re-adjacency                      | Send Hellos (v3: with `LR` bit set per RFC 4811). DBD / LSReq exchange with each pre-restart neighbor; rebuild LSDB. |
| Exit-restart success              | Reconstructed LSDB matches the persisted snapshot (or "compatible" per §3.2 of the RFC) → re-originate self LSAs at `seq + 1`, flush Grace LSAs (MaxAge), clear restarting state. |
| Exit-restart failure / timeout    | Grace period expires before LSDB reconstruction completes, or a mismatch is detected → re-originate fresh LSAs with new content, accept that helpers will have exited. |

## Current state in zebra-rs

| Piece                                                | Status   | Location |
| ---------------------------------------------------- | -------- | -------- |
| `gr_capable` bit in Router Information LSA           | Bit defined, never set | `crates/ospf-packet/src/parser.rs:938` (decoded), `srmpls.rs:36` (only `gr_helper(true)` set) |
| Grace LSA originate path                             | Missing  | codec done in #861; no producer side |
| Pre-restart hook (operator trigger)                  | Missing  | no IPC entry, no vty command |
| LSDB / state checkpoint persistence                  | Missing  | no on-disk store anywhere in `zebra-rs/src/` |
| Skip-`ProtoCleanup` exit path                        | Missing  | `despawn_ospf` (`config/ospf.rs:20`) unconditionally fires `ProtoCleanup`, which withdraws kernel routes |
| Restart-aware startup / cold-start bypass            | Missing  | `Ospf<V>::new` always cold-starts |
| Restarting NFSM behavior (resume neighbors mid-DBD) | Missing  | NFSM enters at `Down`; no "we already knew this neighbor" path |
| LR-bit (v3 Hello option, RFC 4811)                   | Missing  | `Ospfv3Options` bitfield does not carry it |
| Self-originated LSA seq counter persistence          | Missing  | seq starts at `0x80000001` on every cold start (`OspfLsaHeader::new` in `parser.rs:350`) |

## Phased plan

Sub-slice analogous to Phase 2 (`a` / `b` / `c-i` / `c-ii`). Each
phase must land green on its own before the next is queued.

### 5a — Skip-`ProtoCleanup` exit path

Smallest meaningful PR. No GR behavior yet; the prerequisite that
unlocks everything else.

- Add `rib::Message::ProtoQuiesce { proto: String }` (or extend
  `ProtoCleanup` with a `preserve_routes: bool` flag — pick one in
  the open questions below).
- `despawn_ospf` / `despawn_ospfv3` gain an optional "graceful"
  parameter; when set, send `ProtoQuiesce` instead of
  `ProtoCleanup`. The RIB-side handler tears down the
  redistribute subscription and drops the sender but **does not**
  send `RTM_DELROUTE` for the protocol's installed routes.
- Operator-visible surface: none yet; this PR only changes what
  happens on the despawn path *when graceful is asked for*.
  Default behavior is unchanged (`ProtoCleanup`).

Risk: the kernel route ownership model. Today routes carry an
`rtype` and the FIB layer keys teardown off that. If a route is
left behind without a live `rtype` owner, any subsequent
`Ipv4Add` / `Ipv4Del` collision logic has to treat the orphan
route correctly. Verify by killing zebra-rs after this PR and
confirming `ip route` still shows the routes labeled with the
OSPF protocol id.

### 5b — Checkpoint storage layer

Pure scaffolding: serde + an on-disk store. No protocol behavior.

- `zebra-rs/src/ospf/checkpoint.rs` carrying:
  - `OspfCheckpoint<V>` struct with: instance config snapshot
    (router-id, areas, links), per-neighbor identities (router-id
    + interface index + Full-state-at-checkpoint), per-area LSDB
    (keys + the `(seq, checksum, body-bytes)` tuple for every
    self-originated LSA AND every restarter-snapshotted helper
    LSA), `local_pool` SRLB allocation state, and `lan_adj_sids`
    label map.
  - Atomic write (`tempfile` → `rename`) under
    `/var/lib/zebra-rs/checkpoint/{ospf,ospfv3}.cbor` (or `.toml`
    — see open questions).
  - Read-only `Ospf<V>::load_checkpoint(path)` returns
    `Option<OspfCheckpoint<V>>`; on parse failure or missing file,
    `None` (caller cold-starts).
  - **Not yet wired** into the lifecycle. A debug CLI command
    `clear ip ospf checkpoint write` / `…read` lands here so the
    storage can be exercised independently of GR.

### 5c — Pre-restart Grace LSA flood

Operator-triggered pre-stage. Still no actual restart; just
exercises the originate side of the Grace LSA codec from #861.

- New vty command: `clear ip ospf graceful-restart begin
  [period 120 [reason software-restart]]`.
- Handler:
  1. Build a Grace LSA per active interface (Grace Period,
     Restart Reason, IP Interface Address for v2 / link-state-id
     identifies interface for v3) and originate it as
     `OpaqueLinkLocalGrace` / `Ospfv3LsBody::Grace`.
  2. Flood via the existing per-link flood path (helper sees it
     and enters helper mode for us — manual end-to-end test
     against FRR confirms this PR).
  3. Set `Ospf<V>.restarting = Some(RestartingState { … })` —
     locks out config changes; SPF still runs; LSA refresh timers
     stop firing (we must not re-originate at higher seq during
     restart, RFC 3623 §3).
- Set the `gr_capable` bit in `router_info_lsa_build`
  (`srmpls.rs:36`) when restart-capable; mirror the v3 path if it
  exists.
- **No actual exit yet.** This PR shows we can pretend to be
  restarting without breaking the data plane; helpers around us
  enter helper mode. A `clear ip ospf graceful-restart abort`
  walks the restart back.

### 5d — Exit + checkpoint write + skip-cleanup

Wires 5a + 5b + 5c into the actual exit path.

- `clear ip ospf graceful-restart commit` extends the 5c sequence:
  - Floods Grace LSAs (5c).
  - Writes the checkpoint (5b).
  - Sleeps briefly (drain window — 100ms? Tunable) so the Grace
    LSAs reach the wire before the socket closes.
  - Despawns the protocol task with the `graceful=true` flag (5a)
    so `ProtoQuiesce` runs instead of `ProtoCleanup`.
  - The supervisor (systemd / operator) then restarts the
    process. Out of band of this PR — we just provide the clean
    exit and trust the supervisor wraps it.

### 5e — Restart-aware startup + re-adjacency

The other half: pick up the checkpoint on the next boot.

- `Ospf<V>::new` (and the v3 mirror) check for a recent checkpoint
  (configurable "freshness" — within the grace period of the
  Grace LSA in the checkpoint). If present:
  - Skip the normal cold-start LSA origination.
  - Pre-populate `links`, `areas`, `lsdb_as`, `lan_adj_sids`,
    `local_pool` from the checkpoint.
  - Pre-populate neighbors at their last-known router-id +
    interface index, NFSM state `Down` (Hellos will drive them
    back to Full via the standard path).
  - Self-originated LSAs: restore body + seq from the
    checkpoint — do not re-originate yet.
  - Set `Ospf<V>.restarting = Some(RestartingState { … })`.
- During restart, when a Hello arrives from a checkpointed
  neighbor, enter `ExStart` with the pre-restart seq; rebuild
  LSDB via DBD/LSReq.
- Once **all** checkpointed neighbors have reached Full AND the
  reconstructed LSDB matches the checkpoint:
  - Exit-restart success: re-originate self LSAs at `seq+1`,
    flush Grace LSAs (MaxAge), clear `restarting`, delete the
    checkpoint file.
- If the grace period expires first or a mismatch is detected:
  - Exit-restart failure: re-originate self LSAs with new
    content, accept that helpers will exit. Same cleanup
    (`restarting=None`, delete checkpoint).

### 5f — v3 LR-bit signaling

OSPFv3 only. RFC 5187 §2.2 + RFC 4811 — set the LR bit in
outgoing Hellos while restarting. Helpers that didn't catch the
Grace LSA still detect "this neighbor is restarting" from the
Hello.

- Extend `Ospfv3Options` bitfield (currently `crates/ospf-packet/src/v3.rs`)
  with an `lr` accessor. Decode-only is already shipped; emit
  side gates on `Ospf<Ospfv3>.restarting.is_some()`.
- v2 has no analogue; v2 uses the Grace LSA as sole signal.

### 5g (deferred) — Cross-area / ABR / ASBR restart

Restarter as ABR / ASBR raises consistency questions for
Type-3 / Type-4 / Type-5 LSA re-origination. Initial v2 helper
support already shipped multi-area (helpers don't care about ABR
status). For the restarter side, single-area first; ABR work is
its own follow-up doc.

## Non-goals (explicitly deferred indefinitely)

- **Hot-restart via process exec**. RFC 3623 doesn't require
  exec-in-place; a cold restart via the supervisor works. Skip
  hot-restart unless an operator can articulate a benefit beyond
  what GR already provides (5d's drain window covers the
  bounded-downtime case).
- **Restarting-while-helping**. The restarter can theoretically
  be a helper for *other* neighbors simultaneously; handle this
  in a polish PR after 5e proves stable.
- **MD5 / crypto-auth sequence preservation across restart**.
  RFC 2328 §D.5 anti-replay state is now persisted per-neighbor
  (PR #870 added `auth_md5_last_seq`). Preserving it across a
  restart prevents the post-restart Hellos from being rejected
  as replays. Either checkpoint the seq alongside everything
  else (extra field on `OspfCheckpoint<V>`), or accept that the
  first few Hellos after restart will be dropped until the peer
  resyncs. Punt to a polish PR.
- **Concurrent v2 + v3 restart**. Each instance checkpoints
  independently. No coordination layer.

## Open questions (must answer before 5a)

1. **`ProtoCleanup` vs `ProtoQuiesce`** — extend the existing
   message with a flag, or add a new variant? The RIB-side code
   path is the same modulo "send RTM_DELROUTE or don't". I lean
   toward a new variant for callsite clarity at
   `despawn_ospf` (`config/ospf.rs:24`), but the user may prefer
   the flag.
2. **Checkpoint format**. CBOR (`serde_cbor` / `ciborium`) is
   compact + binary; TOML is human-readable but bloats the LSA
   bodies. LSAs are 50-500 bytes each, an LSDB might hold 100s.
   Recommend CBOR + a `clear ip ospf checkpoint dump` show
   command that pretty-prints it.
3. **Checkpoint location**. `/var/lib/zebra-rs/` requires a
   packaging change (the systemd unit must create the dir
   `StateDirectory=`). Alternative: `~/.zebra-rs/` or a
   configurable path. Recommend `/var/lib/zebra-rs/checkpoint/`
   matching the FRR convention.
4. **Restart trigger surface**. Three candidates:
   - `clear ip ospf graceful-restart {begin,commit,abort}` —
     vty-only, ops type it interactively.
   - SIGUSR1 (or a custom signal) — supervisor-friendly,
     scriptable.
   - YANG action (NETCONF RPC) — most "modern", needs more
     infrastructure than the others.
   Recommend vty first, signal second, YANG-action skip.
5. **Sequence number storage scope**. RFC 3623 §3 wants
   re-flood at the same seq during restart. Need to checkpoint
   the seq of *every* self-originated LSA, including Opaque
   ones (Router-Info, Ext-Prefix, Ext-Link). Significant data
   volume; confirm we're OK persisting full LSA bodies (the
   alternative is rebuilding them from config + neighbor state,
   which risks content drift triggering helper exits).
6. **Drain window length**. 100ms is plausible for LAN; over
   WAN/tunnel the Hello-arrival round-trip pushes this higher.
   Tunable, with a sane default — recommend 200ms default,
   `graceful-restart drain-time <ms>` YANG knob.
7. **Boot-time freshness window**. If the checkpoint is older
   than the grace period in it, treat as stale and cold-start.
   What's the clock source — system time (`SystemTime::now`)
   subject to NTP corrections, or a monotonic since-boot
   timestamp from the supervisor? Recommend wall clock with a
   1.5x grace-period slack.
8. **Multi-area neighbors and the LR-bit on v3**. RFC 4811
   places LR in the per-Hello Options; per-interface, but the
   restart is per-instance. Confirm we set LR on *all* v3
   Hellos while restarting (yes — the bit is per-packet, the
   restart is per-router).

## Interactions with neighboring work

- `ospfv3-followups.md` — "Self-originated LSA flush on
  `despawn_ospfv3`" overlaps with 5a. The follow-up there wants
  to MaxAge-flush self LSAs before the despawn drops the
  socket. For GR-clean exit (5d), we want the OPPOSITE — leave
  the self LSAs alive so the helper's snapshot stays valid.
  Resolution: the polite-shutdown path (no GR) still
  MaxAge-flushes; the GR exit path (5d) does NOT.
- BGP / IS-IS graceful-shutdown PRs (#809, #810) operate at the
  redistribute layer, not the protocol-restart layer. No direct
  interaction.

## Estimated PR sizing

| PR    | Subject                                          | Estimated LoC |
| ----- | ------------------------------------------------ | ------------- |
| 5a    | `ProtoQuiesce` exit path                         | ~150          |
| 5b    | Checkpoint storage layer + `clear … checkpoint`  | ~400          |
| 5c    | Pre-restart Grace LSA originate + `gr_capable`   | ~250          |
| 5d    | Wire 5a+5b+5c into the actual exit path          | ~200          |
| 5e    | Restart-aware startup + re-adjacency             | ~500          |
| 5f    | v3 LR-bit signaling                              | ~100          |
| 5g    | (deferred) ABR / ASBR restart                    | —             |
| **Total** | **(5a–5f)**                                    | **~1600**     |

5e is the largest and the riskiest; consider sub-slicing into
"load checkpoint + skip cold-start" and "drive re-adjacency
to exit-restart" once we're closer.
