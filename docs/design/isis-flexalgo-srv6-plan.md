# IS-IS Flex-Algorithm over SRv6 — implementation plan

Status as of 2026-06-16. Tracks the work to extend IS-IS Flexible
Algorithm (RFC 9350) from the SR-MPLS dataplane (complete) to the
SRv6 dataplane (RFC 9352 §7–8). Companion to
`docs/design/flex-algo-roadmap.md`, which covered the SR-MPLS path
and pre-scoped the SRv6 work as its §5; this document supersedes that
§5 with the current code state and an agreed scope.

## Implementation status (2026-06-16)

PRs 1–6 are **implemented** on branch `isis-flexalgo-srv6` (build / fmt /
workspace-clippy / full non-bdd test suite all green; 1 new lsdb parse
unit test). Summary of what landed:

- **PR 1** — per-algo locator watch + End SID alloc: `Isis::{watched_flex_algo_locators,
  sr_flex_algo_locators, sr_flex_algo_end_sid}`, `reconcile_locator_watch`
  now diffs the union of base + per-algo names, `update_flex_algo_end_sid`,
  `process_sr_rx` applies snapshots to every subscriber, config handler
  wired (`inst.rs`, `config.rs`).
- **PR 2** — emit per-algo SRv6 Locator TLV 27 (Algorithm = N) in
  `lsp_generate`, `srv6_end_structure` helper; per-algo locators are *not*
  added to the IPv6-reach advert (separation rule) (`lsp.rs`).
- **PR 3** — `srv6::Srv6AlgoLoc`, `Isis::peer_algo_srv6` threaded through
  IsisTop/LinkTop/SysStateRefs (all sites), parsed in
  `lsdb::rebuild_sys_state` (base `Algo::Spf` → `srv6_end_map`,
  `FlexAlgo(N)` → `peer_algo_srv6`) + clear-on-purge + unit test
  (`srv6.rs`, `inst.rs`, `link.rs`, `lsdb.rs`).
- **PR 4** — `Isis::rib6_flex_algo`, `build_rib6_from_flex_algo` (routes
  each participating node's per-algo locator over the algo-N SPF with a
  plain IPv6 nexthop), `diff_apply_flex_algo6` installs them as real
  `Ipv6Add`/`Ipv6Del` FIB routes (`rib.rs`, `inst.rs`). End SID stays
  cached for the future colour consumer (PR 7).
- **PR 5** — orchestration reads `dataplane_sr_mpls`/`dataplane_srv6` to
  pick which RIB build runs (backward-compatible default: no flag → SR-MPLS)
  (`rib.rs`).
- **PR 6** — `show isis flex-algo` shows local + peer per-algo locators;
  `show isis flex-algo route [algorithm N]` renders the SRv6 per-algo RIB
  alongside the SR-MPLS one (no new exec.yang grammar) (`show.rs`); BDD
  `@isis_flex_srv6` feature + 5 node configs + doc. Also broadened the
  SRv6 capability/SR-Algorithm advertisement gate in `lsp.rs` so an
  SRv6-only Flex-Algo config (no base locator) still advertises
  participation.

**PR 7 — BGP colour → SRv6 service steering: implemented** (branch
`isis-flexalgo-srv6-steering`, build/fmt/clippy/non-bdd tests green; 4
new resolver unit tests). The SRv6 twin of the SR-MPLS colour resolver:

- IS-IS exports, per (algo, prefix reachable in algo-N), the advertising
  node's algo-N End SID (`build_flex_algo_srv6_export` +
  `diff_apply_flex_algo_srv6` → `Message::FlexAlgoSrv6RouteAdd/Del`;
  diff state in `Isis::flex_algo_srv6_export`). Full mirror of the
  SR-MPLS shadow keying, value = node End SID (SRv6 has no per-prefix
  SID).
- RIB fans it out (`RibRx::FlexAlgoSrv6RouteAdd/Del`, no persistent
  shadow — same delivery model as SR-MPLS re-broadcast).
- BGP shadows it in `flex_algo_srv6_routes` (`FlexAlgoSrv6Shadow`, v4 +
  v6 tries) and, in `fib_install_v4`/`fib_install_v6`, LPMs a coloured
  plain-unicast route's next-hop and imposes `segs=[End SID]` + H.Encap
  (`resolve_flex_algo_srv6`). Gated `uni.segs.is_empty()` so a route
  already carrying a service SID is left untouched.
- Also broadened the SRv6 SR-Algorithm advertise gate so SRv6-only
  flex-algo participates without a base locator (already in PR 6).

Scope: plain IPv4 + IPv6 unicast steering. Deferred from PR 7: SRv6
L3VPN steering (prepend End SID before the End.DT4/DT6 service SID).

**PR 8 — per-algo TI-LFA over SRv6: implemented** (branch
`isis-flexalgo-srv6-tilfa`, build/fmt/clippy/non-bdd tests green).
Per-algo fast-reroute for the SRv6 dataplane:

- `compute_spf` runs TI-LFA in each algo's *constrained* graph
  (`FlexAlgoInput.ti_lfa` / `FlexAlgoOutput.tilfa`), gated on the
  per-algo `fast-reroute ti-lfa` toggle AND `dataplane srv6` (set in
  `build_spf_input`). Per-algo TI-LFA stats are not merged into the
  `show isis spf` figures.
- `build_repair_path_srv6` gained an `algo: Option<u8>` param; node
  (End) segments resolve to the algo-N End SID via `node_sid_info`
  (`peer_algo_srv6`) so the repair stays in the algo-N topology, while
  adjacency (End.X) segments reuse the algo-0 End.X — the final
  single-hop into the repair link, processed at the node the prior
  algo-N node segment already delivered to (correct, and avoids a
  produce-side change).
- `build_rib6_from_flex_algo` stamps the backup on each single-nexthop
  per-algo locator route; ECMP routes are self-protecting; a repair
  whose segments can't all resolve is dropped (no partial install).

**Per-algo End.X SID origination: implemented** (branch
`isis-flexalgo-srv6-endx`, build/fmt/clippy/non-bdd tests green) — the
refinement deferred from PR 8 so adjacency repair segments use algo-N
End.X rather than reusing algo-0:

- Each adjacency now derives a per-algo End.X SID from the *same* ELIB
  function as the algo-0 End.X, placed under each per-algo locator's
  prefix (`Neighbor::algo_endx_sids`, reconciled in
  `reconcile_algo_endx_sids`) — no extra function allocation. Registered
  in the FIB like algo-0 (main seg6local End.X + uSID LIB twin), released
  with the algo-0 End.X.
- Emitted as `Srv6EndXSid`/`Srv6LanEndXSid` with Algorithm=N at both the
  main and MT2 IS-Reach emit sites (`srv6_algo_endx_subs`; behavior from
  the per-algo locator via the refactored `srv6_{end,endx,sid}_structure`
  helpers).
- `srv6_endx_sid_for_link` now selects by algo (prefer Algorithm=N, fall
  back to algo-0 `Spf`) — required once multiple End.X sub-TLVs are
  advertised per adjacency; `build_repair_path_srv6` passes the repair's
  algo through.
- `LinkTop` carries the per-algo locator snapshots so the per-Hello
  reconcile can derive the SIDs. Limitation: per-algo End.X requires a
  base (algo-0) locator (the shared function source); without one, repair
  adj segments fall back to nothing (node-segment repairs only).

**SRv6 service-route colour steering (prepend): implemented** (branch
`isis-flexalgo-srv6-vpn-steer`, build/fmt/clippy/non-bdd tests green) —
the "prepend" counterpart of PR 7's plain-unicast "replace":

- `steer_srv6_vpn` / `steer_srv6_vpn_inner` (`bgp/route.rs`) prepend the
  egress PE's algo-N End SID before an existing End.DT4/DT6 service SID
  (`segs = [algoN-End-SID, service-SID]`). The service SID is itself
  under the PE's locator, so LPM-ing it against the colour shadow yields
  the PE's algo-N End SID — no separate next-hop lookup. Called in
  `fib_install_v4` / `fib_install_v6` for routes carrying a service SID
  (mutually exclusive with the plain-path block, which only fires when
  `segs` is empty). 3 unit tests.
- **Effective now** for global SRv6-IPv6-unicast service routes
  (RFC 9252), which install on the main task where the colour shadow is
  in scope. **No-op for per-VRF VPNv4/VPNv6-over-SRv6 routes**: those
  install in per-VRF tasks that don't hold the (dynamic) colour shadow.

Remaining deferred follow-ups: **per-VRF VPN colour steering** — needs a
live global→VRF sync of `flex_algo_srv6_routes` (+ `color_policy`) to
each VRF task (a new `BgpVrfMsg` broadcast on every IS-IS SPF + per-VRF
storage + use in the per-VRF `fib_install`); and a **TI-LFA BDD** (the
PR-6 `isis_flex_srv6` topology has no intra-algo redundancy to exercise
a repair). The PR-6 BDD feature was authored but not executed here
(needs root/netns; CI runs the bdd suite).

## Decisions (locked 2026-06-16)

- **Install model:** per-algo locator prefixes are installed as **real
  IPv6 FIB routes** computed over the algo-N topology (operator can
  ping/traceroute a per-algo locator), *and* the per-algo End SID is
  cached for a later BGP colour-aware steering consumer. Per-algo SRv6
  reachability is plain longest-prefix IPv6 — the algorithm is encoded
  by *which locator you target*, not by a pushed SID.
- **Scope (this effort):** IGP reachability first — PRs 1–6
  (originate → parse → per-algo IPv6 RIB → dataplane gate → show →
  BDD). BGP colour→SRv6 steering (PR 7) and per-algo TI-LFA (PR 8)
  are deferred.

## Why SRv6 flex-algo ≠ SR-MPLS flex-algo

SR-MPLS routes a destination *prefix* by pushing that prefix's
**per-algo Prefix-SID label** (`peer_algo_sid[(algo, prefix)]` →
origin SRGB → label). SRv6 is structurally different:

- Each node advertises a **distinct per-algo locator** (a different
  IPv6 prefix per algorithm) in SRv6 Locator TLV 27 with
  `algo = FlexAlgo(N)`.
- Reaching a node "in algo N" = routing to its **algo-N locator
  prefix**, computed over the algo-N constrained topology. Transit is
  plain IPv6 — no per-prefix SID lookup.
- The per-algo **End SID** (function 0 of the per-algo locator) is what
  a headend/colour-resolver encapsulates toward (H.Encap) to steer a
  service into algo N.

**Separation rule (critical):** per-algo locators must be advertised
**only** in TLV 27 (algo=N), **never** as plain IPv6 Reachability TLVs.
Otherwise algo-0 SPF would also install a route to them over the
unconstrained path and defeat the constraint. The algo-N IPv6 RIB build
sources its destinations from the parsed per-(peer, algo) locator
cache, not from generic IPv6 reachability.

## Current state (verified 2026-06-16)

### SR-MPLS flex-algo — complete, the template to mirror

- FAD codec `IsisSubFlexAlgoDef` — `crates/isis-packet/src/sub/cap.rs`
  (no dataplane field on the wire; RFC 9350 defines none — dataplane is
  config-only).
- Per-algo constrained SPF — `graph_flex_algo()`
  (`zebra-rs/src/isis/graph.rs:548`): peer participation filter
  (`peer_algos`), affinity gate (`flex_algo::constraint::link_passes_fad`),
  IGP + min-delay metric. Result in `spf_flex_algo`. **AF-agnostic — the
  SRv6 RIB build reuses this result as-is.**
- Per-algo IPv4 RIB — `build_rib_from_flex_algo()`
  (`zebra-rs/src/isis/rib.rs:1504`) →
  `rib_flex_algo: Levels<BTreeMap<u8, PrefixMap<Ipv4Net, SpfRoute<V4>>>>`.
- Export — `make_flex_algo_route` → `rib::api::FlexAlgoRoute`
  (`Ipv4Net` + `label: u32`) → `Message::FlexAlgoRouteAdd/Del` →
  consumed by the BGP colour-aware resolver (`Rib::flex_algo_routes`),
  *not* installed as plain FIB routes.

### SRv6 (algo-0) machinery — reusable

- TLV 27 codec `Srv6Locator { algo: Algo, locator: Ipv6Net, subs }`
  (`crates/isis-packet/src/sub/prefix.rs:761`) **already carries the
  Algorithm field**. End.X codec `IsisSubSrv6EndXSid { algo: Algo, … }`
  (`neigh.rs:925`) too.
- Single-locator watch — `reconcile_locator_watch()` + `watched_locator`
  / `sr_locator: Option<Locator>` / `sr_end_sid: Option<Ipv6Addr>` /
  `elib: ElibPool` (`zebra-rs/src/isis/inst.rs`). SID math in
  `zebra-rs/src/isis/srv6.rs` (`function_addr`, `ElibPool`).
- Origination — `lsp.rs:742` emits one `Srv6Locator { algo: Algo::Spf }`
  (**hardcoded algo-0**) + End SID; `lsp.rs:1154` advertises the algo-0
  locator as a plain IPv6 Reachability TLV.
- Consume — `lsdb.rs` parses peer TLV 27 →
  `srv6_end_map: Levels<BTreeMap<IsisSysId, Srv6EndSidInfo>>` (sys-id
  only, algo-0 implicit).
- Primary IPv6 forwarding is plain IPv6 (`resolve_sid` for V6 returns
  `None`, `rib.rs:245`); SRv6 segment lists only feed TI-LFA backup
  (`RepairPathSrv6`, `tilfa::build_repair_path_srv6`, shared
  `spf::srv6::pack_carriers`).

### SRv6 flex-algo scaffolding already on the branch (config/model only)

- YANG: `router isis/segment-routing/srv6/flex-algo-locator[algo]/locator`
  + `flex-algo/dataplane/{sr-mpls,srv6,ip}` (`zebra-rs/yang/config.yang`).
- Storage: `IsisConfig::sr_srv6_flex_algo_locators: BTreeMap<u8,String>`
  (`config.rs:492`); `FlexAlgoEntry::dataplane_srv6`
  (`flex_algo/entry.rs`).
- **Both parsed and stored but read by zero logic.** The config handler
  comment defers emit + locator-watch to "the PR that consumes the map"
  (`config.rs:1366`).

## Gap summary

| Layer | SR-MPLS (done) | SRv6 (gap) |
|---|---|---|
| Locator watch | n/a | single-locator only — watch N per-algo locators, resolve, alloc per-algo End SID |
| Origination | FAD/SID emit done | TLV 27 hardcodes algo-0 — emit per-algo sub-locators |
| Consume | `peer_algo_sid` | `srv6_end_map` sys-id-only — need per-(peer, algo) locator + End-SID cache |
| SPF | `graph_flex_algo` ✅ | reuse as-is (graph is AF-agnostic) |
| RIB install | `build_rib_from_flex_algo` (IPv4 + label) | IPv6 twin: routes to per-algo locators over algo-N path |
| Export / API | `FlexAlgoRoute` (Ipv4Net + label) | IPv6/SRv6 variant + msg; install as FIB routes |
| dataplane gate | flags ignored | read `dataplane_srv6`/`sr_mpls` to pick which RIB build runs |
| TI-LFA | per-algo n/a | per-algo End.X + repair (deferred, PR 8) |
| show / BDD | present | extend |

## Plan — ordered PRs

Repo conventions apply to every PR: `cargo fmt` before commit, workspace
clippy (`cargo clippy --workspace --all-targets -- -D warnings`), and any
BDD feature ends with an explicit teardown scenario.

### PR 1 — Per-algo locator watch + End SID allocation

**Size:** medium. **Scope:** generalize the single-locator watch to a set.

- Add `Isis::sr_flex_algo_locators: BTreeMap<u8, Locator>` (resolved
  snapshots) and `Isis::sr_flex_algo_end_sid: BTreeMap<u8, Ipv6Addr>`
  (function-0 node SID per algo).
- `reconcile_locator_watch()` subscribes to the **union** of the algo-0
  locator name and every name in `sr_srv6_flex_algo_locators`; on `SrRx`
  resolve each and compute its End SID (locator network address).
- Wire `config_sr_srv6_flex_algo_locator` to call
  `reconcile_locator_watch()` and re-originate the self LSP (today it is
  storage-only).
- On a per-algo locator prefix change, drop its stale End SID.

**Files:** `inst.rs`, `config.rs`, `lsp.rs` (`target_locator_name` →
locator-name set), `srv6.rs` (helpers if needed).
**Tests:** watch-set computation (union, add/remove); resolve → End SID
(function 0 == network addr); prefix change clears stale SID.

### PR 2 — Emit per-algo SRv6 Locator TLV 27 (algo = N)

**Size:** small. **Scope:** origination only.

- At `lsp.rs:742`, in addition to the algo-0 sub-locator, push one
  `Srv6Locator { algo: Algo::FlexAlgo(N), locator: prefix_N,
  subs: [Srv6EndSid] }` per entry in `sr_flex_algo_locators` that has a
  resolved snapshot and an End SID.
- **Do not** add per-algo locators to the IPv6 Reachability advert
  (separation rule).

**Files:** `lsp.rs`.
**Tests:** LSP build with one flex-algo locator → TLV 27 carries a
second sub-locator with `algo=128` + End SID; codec round-trip.

### PR 3 — Parse + cache peer per-(algo) SRv6 locators

**Size:** medium (mirrors the `peer_algo_sid` cache end-to-end).

- New cache
  `Isis::peer_algo_srv6: Levels<BTreeMap<IsisSysId, BTreeMap<u8, Srv6AlgoLoc>>>`
  where `Srv6AlgoLoc { locator: Ipv6Net, end: Srv6EndSidInfo }`.
- Populate in `lsdb::rebuild_sys_state`: walk peer TLV 27 sub-locators;
  `algo == FlexAlgo(N)` → cache; `algo == Spf` → existing `srv6_end_map`
  path. Clear on fragment/peer drop.
- Thread the new field through `IsisTop` / `LinkTop` / `SysStateRefs`
  (the ~10 construction sites flagged in the roadmap's cross-cutting
  note — grep `peer_algo_sid` and add next to it everywhere).

**Files:** `inst.rs`, `lsdb.rs`, `srv6.rs`.
**Tests:** ingest a peer LSP with an algo-128 locator → cache
populated; fragment drop clears.

### PR 4 — Per-algo IPv6 RIB build → install per-algo locator routes (FIB)

**Size:** medium-large. **Scope:** the actual SRv6 dataplane.

- Add `Isis::rib6_flex_algo: Levels<BTreeMap<u8, PrefixMap<Ipv6Net, SpfRoute<V6>>>>`
  (mirrors OSPFv3's `rib6_flex_algo`).
- New `build_rib6_from_flex_algo(top, level, algo, source, spf_result)`:
  reuse the existing per-algo `spf_flex_algo` path result (no new SPF);
  for each participating node with `peer_algo_srv6[sys_id][algo]`,
  install a route to that locator prefix with the algo-N IPv6 nexthop(s)
  (`SpfNexthop<V6>`, plain link nexthop, `segs: []`, no encap for
  transit).
- Diff/apply: `diff_apply_flex_algo6` → new `rib::api` IPv6 route type
  (`FlexAlgoRoute6 { algo, prefix: Ipv6Net, metric, nexthops }`) and
  `Message::FlexAlgoRoute6Add/Del`. Per the install decision, the
  RIB-side handler installs these as **real IPv6 FIB routes** (distinct
  per-algo locator prefixes are safe to install).
- Keep the per-algo End SID (`sr_flex_algo_end_sid` local +
  `peer_algo_srv6[..].end` remote) available for the later colour
  consumer (PR 7), but do not wire that consumer here.

**Files:** `inst.rs`, `rib.rs`, `rib/api.rs`, plus the `rib/` install
handler for the new message.
**Tests:** synth LSDB with per-algo locators across a constrained
topology; assert algo-128 IPv6 routes are computed over the constrained
graph (excluded link skipped) with the correct nexthop; metric =
path-cost + locator metric.

### PR 5 — Gate on the `dataplane_*` flags

**Size:** small-medium. **Scope:** pick the right RIB build per algo.

- In the `spf_calc` orchestration (`rib.rs:1199–1461`), read each FAD's
  `dataplane_sr_mpls` / `dataplane_srv6` to decide which build runs:
  SR-MPLS → IPv4 label RIB (existing), SRv6 → IPv6 locator RIB (PR 4).
  Today the V4 build runs unconditionally for every configured algo.
- Confirm the separation rule holds end-to-end: per-algo locators never
  appear in the algo-0 IPv6 RIB.

**Files:** `rib.rs`.
**Tests:** algo with only `srv6` → no IPv4 flex RIB entry; algo with
only `sr-mpls` → no IPv6 flex RIB entry; both → both.

### PR 6 — Operator visibility

**Size:** small-medium.

- Extend `show isis flex-algo`: per-algo SRv6 locators (configured +
  resolved + End SID) and per-peer received per-algo locators.
- Add `show isis ipv6 route algorithm N` reading `rib6_flex_algo`.

**Files:** `show.rs`, `exec.yang`. (Heed the show-grammar/bdd sweep
note: grep old spellings, add `parse()` tests.)

### PR 7 — (deferred) BGP colour → SRv6 service steering

SRv6 twin of `flex_algo_routes`: expose per-algo End SID per node so
colour policy encapsulates coloured service routes (H.Encap) toward the
destination's algo-N End SID. *Files:* `rib/api.rs`,
`bgp/color_policy.rs`, `bgp/inst.rs`.

### PR 8 — (deferred) Per-algo TI-LFA over SRv6

Per-algo End.X SID emit (codec `algo` field already exists) + algo-N
`build_repair_path_srv6` over the algo-N graph and algo-N End/End.X
SIDs. Heavy; defer until base SRv6 flex-algo is validated.

### PR 9 — BDD `isis_flexalgo_srv6`

Mirror the `isis_flexalgo` topology (`bdd/docs/isis_flexalgo.md`) with a
per-algo SRv6 locator per algorithm; assert per-algo IPv6 routes confine
to the constrained sub-topology and that seg6 entries appear in each
namespace's FIB. End with an explicit `Teardown topology` scenario
(stop zebra-rs, delete namespaces, assert the environment is clean).

## Cross-cutting notes

- **Per-peer cache shape:** `peer_algo_srv6` follows the same
  `Levels<BTreeMap<IsisSysId, <inner>>>` shape as `peer_algo_sid` /
  `peer_fad`; update the field on `Isis`/`IsisTop`/`LinkTop`/
  `SysStateRefs` and all `SysStateRefs` construction sites.
- **MT:** the minimal plan runs the algo-N SPF over the default graph
  (single-topology, the common SRv6 case). If an MT2 (IPv6 MT)
  constrained SPF is needed, parameterize `graph_flex_algo` by topology
  as a follow-up — out of scope here.
- **Style references:** new per-peer cache → mirror `peer_algo_sid`
  (PR #619); per-algo locator emit → mirror the algo-0 TLV 27 emit at
  `lsp.rs:742`; IPv6 per-algo RIB → mirror `build_rib_from_flex_algo`
  for control flow and OSPFv3 `rib6_flex_algo` for the storage shape.
