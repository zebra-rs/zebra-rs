# BGP tracing follow-ups

Snapshot of remaining `router bgp tracing` work as of `main` ≈ commit
`12d44135` (PR #1205 merged). The base conditional-tracing system and the
category taxonomy are in place; what's left is coverage breadth (sites not
yet routed through the gates) and a couple of cross-protocol cleanups.

Companion to [`bgp-tracing-plan.md`](bgp-tracing-plan.md) (the original
design). Follow the project's standing guidance before picking an item:
recommend the smallest meaningful slice with its main tradeoff, let the
user redirect, ship one branch / one PR at a time.

## Recently landed (context)

- **#1199** — `BgpTracing` struct + config callbacks + gated macros
  (`bgp_fsm_trace!`, `bgp_packet_trace!`, `bgp_adj_in_trace!`,
  `bgp_adj_out_trace!`, `bgp_label_trace!`) + `zebra-bgp-tracing.yang`.
  Instance-wide **and** per-neighbour scope, additive
  (`Peer::tracing_instance` ∪ `Peer::tracing`).
- **#1202** — gate the dynamic-label-block-granted log on `label`.
- **#1205** — add categories `vpn` / `srv6` / `vrf` / `bfd`; convert the
  parent-instance info/debug sites; new book chapter
  `book/src/ch-02-10-bgp-tracing.md` documenting all categories.

Current category set: `all`, `fsm`, `packet{…}`, `label`, `adj-in`,
`adj-out`, `vpn`, `srv6`, `vrf`, `bfd`.

## Design rule carried forward

Two macro families, by severity:

- **`bgp_<cat>_trace!`** — gated on `should_trace_<cat>()`, emit at
  `info` when enabled. For diagnostic info/debug detail.
- **`bgp_warn!` / `bgp_error!`** — unconditional, stamp `proto="bgp"`.
  For operator-facing warnings/errors that must always surface.

Do **not** hide a warning/error behind a tracing category — turning a
category off must never suppress a real problem. The items below respect
this split.

## Small / one-PR each

### `proto="bgp"` warn/error sweep
~21 raw `tracing::warn!` / `error!` sites in `bgp/` still emit without
`proto="bgp"`, so BGP warnings aren't protocol-filterable like IS-IS /
OSPF. Convert them to `bgp_warn!` / `bgp_error!` (unconditional — see the
design rule above). Sites (≈ line, drifts):

- `inst.rs:94` multi-VRF peer claim; `inst.rs:1109` VRF task gone on
  inbound accept; `inst.rs:2476` / `inst.rs:2755` export dropped — no RD
  (v4 / v6); `inst.rs:3049` RFC 5882 peer teardown on bfd-down.
- `route.rs:5007` / `5031` received NLRI dropped — bad next-hop;
  `route.rs:7875` / `7913` / `8119` EVPN origination guards.
- `config.rs:158` / `171` / `1531` / `1620` / `1648` TCP MD5 / TCP-AO
  setsockopt failures; `config.rs:248` neighbor-group unresolved.
- `peer.rs:1543` OPEN with router-id 0.0.0.0.
- `auth.rs:87` / `262` platform-unsupported no-ops (free functions with
  no `BgpTracing` in scope — `bgp_warn!` is the right fit, they stay
  always-on).

Pure mechanical swap; no behaviour change beyond the added field.

### `adj-out` reuse for advertise-skipped warnings
`route.rs:2077` / `2301` ("peer Established but not in any update-group;
advertise skipped") already hold a `peer`. Decision needed: keep as an
always-on `bgp_warn!` (it signals a real bug — a peer that should be in a
group isn't), or gate under `adj-out`. Leaning **keep as warn** since it's
an invariant violation, not routine adj-out detail. Listed here so the
choice is explicit rather than forgotten.

### `evpn` runtime category vs the `DEBUG_EVPN` compile flag
`route.rs:3648` ("extract_vni_from_attr: RT yields VNI …") is gated behind
the compile-time `DEBUG_EVPN` const. If/when EVPN tracing grows, replace
that const with a runtime `evpn` category (struct field + accessor +
`apply_tracing` arm + macro + YANG leaf, mirroring `vpn`) and fold this
site plus the EVPN warns in `route.rs:7875/7913/8119` under it. Thin today
(one debug line), so deferred until there's more to gate.

### `auth` runtime category (optional, thin)
Only one diagnostic debug line would benefit: `config.rs:1523` ("TCP MD5
installed on listener"). The rest of the auth sites are warnings (covered
by the sweep above). A full `auth` category buys little; record the option
but don't build it unless TCP-AO/MD5 tracing expands.

## Medium

### Per-VRF task tracing propagation
The per-VRF BGP task (`BgpVrf` in `vrf/inst.rs`) has no `BgpTracing`, so
its log sites can't be gated and stay raw:

- `vrf/inst.rs:362` shutdown, `:369` channel closed, `:450` ignored
  Accept, `:812` inbound Accept → would be **`vrf`**.
- `vrf/inst.rs:588` / `646` / `742` / `792` ImportV4/V6 write+withdraw
  (carry `label`) → would be **`vpn`**.
- `vrf/spawn.rs:145` / `256` / `295` / `407` / `413` spawn/despawn
  lifecycle → would be **`vrf`**.

Mechanism: add `tracing: BgpTracing` to `BgpVrf`, seed it from
`bgp.tracing.clone()` in `spawn_bgp_vrf` (the way peers seed
`tracing_instance` at `config.rs:101` / `peer.rs:1823` /
`interface_neighbor.rs:115`). The wrinkle vs peers: a `BgpVrf` runs in its
own tokio task, so a *post-spawn* tracing config change must be pushed to
it over the per-VRF message channel (peers are re-synced in-process by
`config_tracing_dispatch` at `tracing.rs:478`; the VRF task can't be
touched directly). Smallest first slice: seed-at-spawn only, accept that
live re-config of an already-spawned VRF lags until respawn; add the
channel push as a second slice.

### Validation — eyeball the trace output
No category's emitted output has been visually confirmed end-to-end
against a live session (config → enable category → observe `proto="bgp"
category=…` lines). Cheapest payoff: bring up a peer, toggle each category,
confirm the right sites fire and the fields render. Reuse `bdd/` scaffolding
if a scripted check is wanted (currently CI-excluded, locally runnable).

## Cross-protocol (large, out of scope for a BGP-only PR)

### Shared `crate::tracing` core
`IsisTracing`, `OspfTracing` (PR #1203) and now `BgpTracing` independently
duplicate the packet / direction / presence-flag scaffolding and the
`should_trace_*` + gated-macro shape. A generic core they all `uses` would
remove three-way drift. Deferred per "smallest PR first" — each protocol
should keep matching the established per-protocol pattern until someone
takes the unification deliberately. Note this touches all three trees, so
it wants its own plan doc, not a drive-by.
