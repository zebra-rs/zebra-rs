# BGP neighbor local-as — recap & follow-ups

Snapshot as of `main` ≈ commit `8b72dc87` (PR #1404 merged,
2026-06-12). The per-neighbor `local-as` knob (FRR parity, RFC 7705
AS-migration) is shipped end-to-end across three PRs: #1386 (YANG
schema + book chapter), #1398 (wire behavior), #1404 (BDD + the
NOTIFICATION-flush core fix the BDD exposed). This memo records the
design decisions a future session would otherwise re-derive, and the
deliberately deferred slices.

## What shipped

### Schema (PR #1386, `zebra-bgp-local-as.yang`)

- `local-as` is a **single-entry list keyed by `as-number`** so the
  CLI reads `set router bgp neighbor X local-as 64999 [flag true]` in
  FRR's token order and renders `local-as 64999 { … }`. The engine
  does not enforce `max-elements 1`; the config callback refuses a
  second key with a warning (first entry wins, delete before
  changing).
- The three modifiers are **independent boolean leaves** —
  `no-prepend` (inbound), `replace-as` (outbound), `dual-as`
  (session). FRR's CLI nests them for IOS compatibility but its own
  northbound model keeps them independent; we follow the model, not
  the CLI.
- The vendored `ietf-bgp-common` `local-as` leaf was **deleted** (it
  cannot carry the modifiers; a same-named augment is silently
  dropped per RFC 7950 §7.17 — the remove-private-as precedent).
  Pinned by `bgp_neighbor_local_as_is_settable` in
  `zebra-rs/src/config/manager.rs`, including a negative check that
  the value-less flag spelling does not parse.
- Module loading is **import-driven**: the module had to be imported
  from `config.yang` to enter the load graph at all — an augment-only
  module that nothing imports silently never loads, and only the
  settable-path parse test catches it.

### Wire behavior (PR #1398)

`Peer::change_local_as()` is the single source of truth: it returns
`None` both when the knob is off **and while the dual-as fallback
presents the global AS**, so OPEN, both prepends, and the
update-group signature degrade together (mirroring FRR's
`peer->change_local_as` toggling).

- **Session**: OPEN My-AS + AS4 capability carry
  `Peer::open_local_as()`. On a Bad Peer AS NOTIFICATION with
  `dual-as` set, `fsm_bgp_notification` flips
  `peer.local_as_dual_fallback` — the next OPEN presents the other AS
  (FRR's retry scheme, bgp_packet.c). The fallback survives `clear`
  (deliberate: the BDD's clear-then-assert relies on it) and resets
  only on local-as config edits.
- **Inbound**: the substitute is prepended **once per UPDATE** at the
  top of `route_from_peer` (FRR prepends at attr-parse), unless
  `no-prepend`. Every family handler shares `packet.bgp_attr`, and
  Adj-RIB-In stores post-prepend attrs, so soft-reconfig replays
  (which start from `peer.adj_in`) never double-prepend. The 8
  inbound loop-check sites route through `aspath_own_as_loop`, adding
  FRR's substitute-AS check with its budget (bgp_route.c ~5911): 1
  while the prepend is active, 0 under `no-prepend`, a configured
  `allowas-in` count replaces it. **Documented divergence**:
  `allowas-in origin` + active prepend skips the substitute check
  (FRR's budget-0 there drops every route from the peer — a wart, not
  parity worth keeping).
- **Outbound**: `ebgp_egress_aspath` ends with the FRR three-way:
  `substitute, real` (bare), `substitute` only (`replace-as`), plain
  real-AS prepend (off / dual-as fallback active).
- **Update groups**: `local_as_substitute: Option<(u32, bool)>`
  (substitute, replace-as) in `UpdateGroupSig`, eBGP only — peers
  under different substitutes must not share canonical UPDATE bytes.
  Covered by the signature-fields-distinguish unit test.
- **Config callbacks**: entry create/remove bounces a live session
  (the OPEN changes — ttl-security ritual); the modifier leaves do
  not. Guards: substitute ≠ global AS (FRR's error, warn-and-keep),
  single instance. A flag delete must not re-seed an entry the same
  commit already removed (the callbacks are order-independent within
  a commit).
- **Show**: neighbor detail prints the configured form +
  `dual-as fallback active` when toggled; the header's `local AS` is
  the effective AS (FRR prints change_local_as there too);
  `show bgp update-group` displays the substitute in the signature
  block.

### NOTIFICATION flush on teardown (PR #1404, found by the BDD)

The dual-as BDD scenario could not converge: every "send NOTIFICATION
then tear down" path queued the frame on the connection writer's
channel, then **aborted the writer task** (`Task` aborts on drop)
before it flushed — tcpdump showed OPEN then a bare FIN, never the
NOTIFICATION. Counters lie here: they increment at queue time
(sender said `sent: 59`, receiver `rcvd: 0`). Three sites:
`update_timers`' Idle-entry arm, `close_primary`, `close_collision`
(whose comment *claimed* the writer drains); `reject_connection` was
always correct. Fix: `Task::detach()` + at each site drop `packet_tx`
first (closes the channel so the drain terminates), then detach the
writer — the frame drains, the FIN follows it. Pinned by
`detached_writer_drains_queued_frames_before_fin` (socket-pair,
read_to_end proves frame-before-FIN). Without this fix `dual-as`
cannot work between two zebra-rs nodes at all.

### BDD (`@bgp_local_as`)

Two-router topology; z2 still expects the pre-migration AS
(`remote-as 64999`) and is **passive throughout so z1 always dials**
— the dual-as Bad-Peer-AS/retry exchange stays a single deterministic
connection stream (two active dialers can double-toggle the fallback
in one round and oscillate). Scenarios: Established-under-substitute,
bare-form paths both directions (`64999 65100` / `64999 65001` — the
ingress assertion also proves the loop budget admits our own
prepend), replace-as, no-prepend (apply-replace removes replace-as in
the same step), dual-as migration (z2 flips remote-as to the global
AS), explicit teardown.

## Deferred / scope boundaries

None of these block anything; 1–3 are parity-consistent with the
sibling per-neighbor knobs. Listed so a future surface-sweep has a
known list.

1. **Neighbor-group inheritance** — `local-as` is not in
   `zebra-bgp-neighbor-group.yang` nor `InheritableKnobs`. FRR
   supports it on peer-groups (member override semantics in
   `peer_local_as_set`). Adding it: `uses
   zbla:bgp-neighbor-local-as-extension` in the group YANG + the
   explicit/group split and `apply_inherited` lockstep destructure
   per the established architecture. The bounce-on-as-number-change
   ritual must run per member.
2. **VRF BGP instances** — the callbacks are registered only on the
   default instance (`/router/bgp/neighbor/local-as…`). Same gap as
   every other per-neighbor knob; join the sweep if that surface
   grows.
3. **interface-neighbor (unnumbered) peers** — the YANG attaches to
   `neighbor` only. Plausible use (migrating a fabric AS), but none
   of the AS-manipulation knobs are exposed there yet.
4. **4-byte substitute in the 2-octet My-AS field** — the OPEN encode
   does `peer.open_local_as() as u16`, truncating an ASN > 65535;
   RFC 6793 requires AS_TRANS (23456) in the 2-octet field with the
   real value in the AS4 capability. **Pre-existing** for the global
   AS (`peer.local_as as u16` before this series); local-as inherits
   it. Fix belongs in the OPEN encoder, not the local-as code.
5. **Detached writer drain is unbounded** — a wedged peer (zero
   window) keeps the detached drain task alive until the kernel gives
   up. `reject_connection` bounds its equivalent with a 5s timeout;
   the drain path could grow the same bound if task leaks are ever
   observed. Rare: requires a wedged socket *and* queued data at
   teardown.
6. **No FRR-interop run** — the BDD is zebra-rs↔zebra-rs. A
   zebra-rs↔FRR run (each side substituting toward the other,
   dual-as against FRR's vty-driven flip) has not been done. FRR
   flushes notifications synchronously, so the dual-as exchange
   should be *more* robust against FRR than between two pre-#1404
   zebra-rs nodes.
7. **Loop-drop diagnostics name the wrong AS** — the per-family drop
   messages print `peer.local_as` even when the *substitute* check
   tripped (cosmetic; the helper returns only a bool).
8. **Counters count queued, not wired** — `notification sent`
   increments at queue time (`peer_send_notification`), which is what
   made the BDD failure misleading. A wire-time counter (or a
   sent/queued split) would make the next such bug self-diagnosing.

## Code anchors

- `zebra-rs/yang/zebra-bgp-local-as.yang` + the vendored-leaf removal
  in `ietf-bgp-common@2023-07-05.yang`
- `zebra-rs/src/bgp/peer.rs` — `LocalAs`, `change_local_as()` /
  `open_local_as()`, `local_as_dual_fallback`, the
  `fsm_bgp_notification` toggle, `close_primary`/`close_collision`,
  the drain + dual-as unit tests
- `zebra-rs/src/bgp/route.rs` — ingress prepend in `route_from_peer`,
  `aspath_own_as_loop`, `ebgp_egress_aspath`, `local_as_tests`
- `zebra-rs/src/bgp/config.rs` — `local_as_entry` guards,
  `config_local_as` (+ bounce), `config_local_as_flag`
- `zebra-rs/src/bgp/timer.rs` — Idle-entry writer drain
- `zebra-rs/src/context/task.rs` — `Task::detach`
- `zebra-rs/src/bgp/update_group.rs` — `local_as_substitute` in the sig
- `bdd/tests/features/bgp_local_as.feature` + configs
- `book/src/ch-02-28-bgp-local-as.md`
