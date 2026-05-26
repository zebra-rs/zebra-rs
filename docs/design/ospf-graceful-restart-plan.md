# OSPF Graceful Restart — plan

Scoping doc for OSPFv2/OSPFv3 Graceful Restart (GR) support in
zebra-rs. References:

- RFC 3623 — Graceful OSPF Restart (OSPFv2, Grace LSA = opaque
  type 3 under link-local LSA type 9)
- RFC 5187 — Graceful OSPFv3 Restart (Grace-LSA function code 11,
  link-local flooding scope `0x0008`)
- RFC 4811 / 4812 — auxiliary LR-bit signaling. **OSPFv2 only**;
  RFC 5187 makes Grace-LSAs the sole restart signal for v3. The
  earlier mis-attribution of LR to v3 is corrected in
  `ospf-graceful-restart-restarter.md`.
- RFC 7770 — Router Information Opaque LSA (`gr-capable` /
  `gr-helper` bits already wire-decoded today)

Captured on branch `ospf-restart` (matches `main` at the time of
writing — no commits yet) so a future session can pick from a
known starting point.

Follow the standing project guidance: smallest meaningful slice
first, confirm direction before sinking work into follow-on files,
one branch / one PR at a time.

## Current state in-tree

The wire-format scaffolding is partly present. The control-plane
machinery is not.

| Piece                                            | Status   | Location |
| ------------------------------------------------ | -------- | -------- |
| `RouterCapability { gr_helper, gr_capable }`     | Decoded  | `crates/ospf-packet/src/parser.rs:937` |
| GR bits set in originated Router-Info LSA        | Missing  | only `.with_te(true)` at `zebra-rs/src/ospf/srmpls.rs:28` |
| `OpaqueLinkLocal = 9` (RFC 2370 link-local LSA)  | Present  | `crates/ospf-packet/src/ls_type.rs:17` + `FloodScope::Link` at `flood.rs:28` |
| `OpaqueLsaType::Grace = 3` (RFC 3623 §A)         | Missing  | `parser.rs:858` has only `RouterInfo=4 / ExtPrefix=7 / ExtLink=8` |
| Grace-LSA sub-TLV codec (Grace Period / Restart Reason / IP Interface Address) | Missing | — |
| OSPFv3 Grace-LSA (function code 11)              | Missing  | `crates/ospf-packet/src/v3.rs` |
| OSPFv3 LR-bit handling                            | N/A — RFC 5187 §3 doesn't define an LR analogue for v3 | — |
| IETF YANG model on disk                          | Present unused | `zebra-rs/yang/ietf-ospf@2022-10-19.yang` has feature `graceful-restart` + helper identities + status typedefs |
| Project YANG binding (`router ospf {…}`)         | Missing  | no `graceful-restart` container in `zebra-rs/yang/config.yang:310 / :459` |
| Helper state machine                             | Missing  | `nfsm.rs` only runs the inactivity timer |
| Restarting-router state preservation             | Missing  | no LSDB / route-table checkpoint exists anywhere in zebra-rs |
| `show … graceful-restart`                        | Cosmetic | `show.rs:372` hard-codes `"Graceful Restart hello delay: 10s"` with no underlying logic |

Note on RFC 2328 §13.4 (`inst.rs:2683`): the existing "peer
flooded our own LSA back at higher seq → re-originate" path is
cold-restart recovery (MaxSeqAdvance), not Graceful Restart. It
covers correctness after a non-graceful exit, not adjacency
preservation across a planned restart.

## Why helper-only first

RFC 3623 §3 explicitly defines helper-only mode. It is roughly
half the deployed value of GR (your peers' planned restarts stop
blackholing traffic through you) at a small fraction of the
implementation cost:

- No persistent state required. Helper mode is pure
  receive-side: detect Grace LSA → suppress the neighbor's
  adjacency timeout → exit on grace period expiry or topology
  change.
- Testable against FRR. v2 + v3 are FRR-validated to Full state
  (`[[zebra-rs-ospf-v2-frr-validated]]`,
  `[[zebra-rs-ospf-v3-frr-validated]]`), and FRR has full
  restarting-router GR support — so we can be the helper to
  a real restarter immediately.
- Restarting-router mode requires checkpointing the LSDB +
  computed routes + neighbor identity across a process restart,
  which zebra-rs has no infrastructure for today. That is a
  separate scoping problem and should not block helper mode.

## Phase 1 — Grace LSA codec (`crates/ospf-packet`)

Smallest meaningful PR. No protocol behavior change, no
config-surface change.

1. Extend `OpaqueLsaType` (`parser.rs:858`) with `Grace = 3` and
   matching constants in the `impl` block. Verify the existing
   `OspfLsp::OpaqueLinkLocal*` arms (the type-9 link-local scope
   already routes through `FloodScope::Link`) hand a Grace LSA
   body to a new `GraceLsa` parser.
2. Add `GraceLsa` body with sub-TLVs (RFC 3623 §A.1):
   - Type 1 — Grace Period (uint32 seconds)
   - Type 2 — Graceful Restart Reason (uint8: 0 unknown,
     1 software restart, 2 software reload/upgrade,
     3 switch to redundant CP)
   - Type 3 — IP Interface Address (Ipv4Addr; v2 only — for
     unnumbered interfaces, identifies the sending interface)
   Use the same TLV macro pattern already established by
   `RouterInfoTlv` / `ExtPrefixTlv`.
3. Mirror in `crates/ospf-packet/src/v3.rs`: function code 11,
   link-local flooding scope `0x0008`; same first two sub-TLVs
   (no v3 IP Interface Address — RFC 5187 §2.1).
4. Decode-only `show ip ospf database opaque-link` /
   `show ipv6 ospf database link` rendering (mirror existing
   `show_router_info_detail` shape in `show.rs:1282`).
5. Fixture decode tests under `crates/ospf-packet/tests/`. Use
   the FRR-emitted Grace LSA as the golden capture if available;
   otherwise hand-construct.

Exit criteria: `cargo fmt && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace`
all clean, decode round-trips fixture bytes, `show` prints a
human-readable Grace LSA when one is in the LSDB.

## Phase 2 — OSPFv2 helper mode

1. **Neighbor state extension.** Add `helper: Option<HelperState>`
   to `Neighbor`. `HelperState { grace_period_deadline,
   restart_reason, entered_at, lsdb_snapshot_seq }`. Reset on
   helper exit.
2. **Grace LSA receive path.** When a Grace LSA arrives on an
   interface from a neighbor:
   - Validate (grace period ≤ configured max, reason is
     accepted by policy, sender is a Full neighbor or was just
     before — RFC 3623 §3.1).
   - Per-interface helper-policy gate (`strict-lsa-checking`
     etc., see Phase 4 config).
   - Mark neighbor `helper = Some(…)` and start a grace timer.
3. **Suppress neighbor down.** In `ospf_nfsm_inactivity_timer`
   (`nfsm.rs`), if `nbr.helper.is_some()`, do not transition
   to Down; let the helper-exit logic drive the transition.
4. **Preserve advertised adjacency.** In Router-LSA / Network-LSA
   origination, treat helper-mode neighbors as if still Full so
   we keep listing the link/neighbor. Verify the
   `network_lsa_flush` (`inst.rs`, RFC 2328 §14.1) path doesn't
   prematurely flush when the only "down" neighbor is actually
   in helper.
5. **Helper exit conditions** (RFC 3623 §3.2):
   - Grace period expires (timer fires).
   - LSA flooded into the area that changes the topology
     advertised by the restarting router (i.e. any LSA whose
     advertising-router != restarter, *or* a Router/Network/
     Summary LSA from the restarter inconsistent with the
     pre-restart LSDB snapshot). Implement by snapshotting the
     restarter's LSAs at helper entry and comparing on each
     flood event for that area.
   - Inactivity timer would have fired anyway after a fresh
     adjacency comes back to Full (clean exit, the common case).
   On exit, clear `nbr.helper`, re-run NFSM as if the inactivity
   timer had fired in the failure case, or just clear state in
   the success case. Re-run SPF.
6. **`gr_helper` capability bit.** Set in
   `srmpls.rs:router_info_lsa_build` when helper mode is
   enabled (Phase 4 config).
7. **`show ip ospf graceful-restart`** — per-interface +
   per-neighbor helper status table, exit-reason history (small
   ring buffer on the area or instance).

Exit criteria: against FRR `ospfd` configured with
`graceful-restart`, FRR restarting cleanly does not flap the
adjacency from zebra-rs's POV; routes through the restarter
stay installed for the full grace period; SPF does not re-run.

## Phase 3 — OSPFv3 helper mode

Same shape as Phase 2 against the v3 path. Extra wrinkles:

- Grace-LSA function code 11, link-local scope `0x0008`
  (`packet_v3.rs`).
- ~~RFC 4811 LR-bit handling.~~ Confirmed v2-only after a
  re-read of RFC 5187 §3 — v3 has no LR analogue. Grace LSA
  is the sole restart signal. No Hello-options work needed
  on the v3 helper.
- Network-LSA equivalent is the Network-LSA (`type 0x2002`) +
  Intra-Area-Prefix-LSA (`type 0x2009`). Both must keep
  advertising the helper-mode neighbor.

## Phase 4 — Config + show plumbing

Concurrent with Phase 2 (small enough that splitting is more
overhead than value):

- Add to `zebra-rs/yang/config.yang`'s `container ospf {…}` and
  `container ospfv3 {…}`:
  ```
  container graceful-restart {
    leaf helper-enabled { type boolean; default true; }
    leaf helper-strict-lsa-checking { type boolean; default true; }
    leaf max-grace-period { type uint32; default 1800; units seconds; }
    leaf-list helper-reason { type identityref { base gr-reason; } }
  }
  ```
  Defaults reflect RFC 3623 guidance — helper on, strict
  checking on, 30-minute max grace.
- Wire callbacks in `zebra-rs/src/config/ospf.rs` /
  `config_v3.rs`.
- Replace the cosmetic `show.rs:372` `"Graceful Restart hello
  delay: 10s"` line with real per-instance helper status.

## Phase 5 (deferred) — Restarting-router mode

Out of scope for the first GR series and now scoped in detail in
`ospf-graceful-restart-restarter.md`. The big-picture gaps are:

- LSDB / per-instance state checkpoint to disk before planned
  exit, restored at next boot before adjacencies come back.
- Skip-`ProtoCleanup` exit path so kernel routes survive the
  daemon restart (today's `despawn_ospf` unconditionally
  withdraws them).
- Pre-exit Grace LSA flood with a drain window before the raw
  socket closes.
- Self-originated LSA seq + body persistence so re-flood after
  restart matches helpers' snapshot (RFC 3623 §3).

**Status (2026-05-26):** OSPFv2 restarter complete on `main`
(PRs #888 / #900 / #904 / #905 / #907 / #908). OSPFv3 restarter
is the remaining series item — see the "5f — v3 restarter
mirror" section of the restarter doc; it needs its own
scoping pass before pickup.

## Branch / PR shape

One branch per phase, off `main` (re-base before opening):

- `ospf-grace-lsa-codec` — Phase 1
- `ospf-v2-gr-helper` — Phase 2
- `ospf-v3-gr-helper` — Phase 3
- `ospf-gr-config` — Phase 4 (can fold into Phase 2 if small;
  decide at review time)

Each PR runs the workspace gates locally before push:
`cargo fmt && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace`
(per `[[feedback-cargo-fmt-before-commit]]` and
`[[feedback-clippy-workspace-not-crate]]`).

## Open questions

- ~~**OSPFv3 LR-bit policy.**~~ Answered 2026-05-26: RFC 5187
  §3 makes Grace-LSAs the sole v3 signal; no LR analogue is
  defined for v3. RFC 4811 LR is OSPFv2-only.
- **`helper-strict-lsa-checking` default** — RFC 3623 §3.2
  recommends strict (exit on any topology change in the area
  during helper); some operators relax. Default strict, expose
  the knob.
- **Grace LSA on shutdown when only helper-mode is supported.**
  RFC 3623 §3 allows a helper-only implementation to never
  originate Grace LSAs. We will follow that — Phase 1 codec is
  bidirectional, but the originate path is wired in Phase 5.
- **YANG identity vs enum for `helper-reason`.** Match the
  IETF model (`ietf-ospf@2022-10-19.yang` identityrefs) if we
  ever expect to consume that model; otherwise an enum is
  simpler. Recommend matching IETF — the schema is already in
  the tree.
