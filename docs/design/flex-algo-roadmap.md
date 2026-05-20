# IS-IS Flex-Algorithm — implementation roadmap

Status as of 2026-05-20. Tracks the remaining work for RFC 9350
Flexible Algorithm support in IS-IS.

## What's landed

Nine PRs across produce and consume sides:

| PR | Subject | Files | RFC |
|---:|---|---|---|
| [#605](https://github.com/zebra-rs/zebra-rs/pull/605) | YANG schema + `FlexAlgoConfig` builder | `zebra-rs/yang/config.yang`, `zebra-rs/src/isis/flex_algo.rs` | RFC 9350 §4 |
| [#609](https://github.com/zebra-rs/zebra-rs/pull/609) | Remaining config trees (affinity-map, per-link affinity, per-algo SID, per-algo SRv6 locator) | `affinity_map.rs`, `link.rs`, `config.rs` | RFC 7308, RFC 9350 |
| [#610](https://github.com/zebra-rs/zebra-rs/pull/610) | FAD sub-TLV emit (codec + LSP origination) | `crates/isis-packet/src/sub/cap.rs`, `lsp.rs` | RFC 9350 §5.1 |
| [#612](https://github.com/zebra-rs/zebra-rs/pull/612) | SR Algorithm sub-TLV participation | `flex_algo::sr_algorithms`, `lsp.rs` | RFC 9350 §5.2, RFC 8667 §3.2 |
| [#613](https://github.com/zebra-rs/zebra-rs/pull/613) | Per-link ASLA Extended Admin Group emit | `flex_algo::build_link_asla`, `lsp.rs` | RFC 9479, RFC 7308 |
| [#614](https://github.com/zebra-rs/zebra-rs/pull/614) | Per-algo Prefix-SID emit (SR-MPLS) | `flex_algo::build_per_algo_prefix_sids`, `lsp.rs` | RFC 8667 §2.1, RFC 9350 §7 |
| [#615](https://github.com/zebra-rs/zebra-rs/pull/615) | FAD parse + `Isis::peer_fad` cache | `lsdb.rs::rebuild_sys_state` | RFC 9350 §5.1 |
| [#616](https://github.com/zebra-rs/zebra-rs/pull/616) | Per-link ASLA parse + `Isis::peer_link_affinity` | `flex_algo::parse_asla_flex_algo_bitmap` | RFC 9479 |
| [#619](https://github.com/zebra-rs/zebra-rs/pull/619) | Per-algo Prefix-SID parse + `Isis::peer_algo_sid` | `flex_algo::parse_per_algo_prefix_sids` | RFC 8667, RFC 9350 §7 |

## State after PR #619

What's reachable in `Isis`:

- `flex_algo: FlexAlgoConfig` — local FAD configuration (algo, metric-type,
  priority, dataplane flags, affinity/SRLG constraints, ti-lfa override).
- `affinity_map: AffinityMap` — named admin-group → bit-position table.
- `peer_fad: Levels<BTreeMap<IsisSysId, BTreeMap<u8, IsisSubFlexAlgoDef>>>` —
  FADs received from peers, keyed by (peer, algo).
- `peer_link_affinity: Levels<BTreeMap<IsisSysId, BTreeMap<IsisNeighborId, ExtAdminGroup>>>` —
  per-link Extended Admin Group bitmaps from peer LSPs.
- `peer_algo_sid: Levels<BTreeMap<IsisSysId, BTreeMap<(u8, Ipv4Net), SidLabelValue>>>` —
  per-(peer, algo, prefix) Prefix-SID labels from peer LSPs.

What's NOT yet computed or installed:

- No per-algo SPF runs. The legacy / MT graph builder still ignores the
  flex-algo caches above.
- No per-algo entries in `Isis::rib` / `Isis::ilm`. Per-algo SIDs sit in
  `peer_algo_sid` but never reach the kernel.
- `SR Algorithm` participation from peers is parsed into `LspCapView.algo`
  but never cached or used for SPF filtering.

## Remaining work — ordered by recommended sequence

### 1. SR Algorithm participation parse → `peer_algos` cache

**Size:** small (≈100 lines, mirrors PR #615/#616/#619).
**Scope:** add `Isis::peer_algos: Levels<BTreeMap<IsisSysId, BTreeSet<u8>>>`
populated in `lsdb::rebuild_sys_state` from `LspCapView.algo`. Includes
algo IDs (0, 1, 128..255). Cleared on peer purge.

**Why before SPF gating:** SPF must drop peers that don't advertise the
algo it's computing. Cache makes the filter a one-line lookup;
without it, SPF gating has to walk the LSDB per peer per SPF run.

**Files to touch:**
- `zebra-rs/src/isis/inst.rs` — add field, thread through `IsisTop` /
  `LinkTop`.
- `zebra-rs/src/isis/lsdb.rs` — `SysStateRefs::peer_algos`, ingest in
  `rebuild_sys_state` from `LspCapView.algo.algo`.
- 10 `SysStateRefs` construction sites (2 production + 8 test).

**Test plan:**
- `flex_algo` helper test: empty algo list → empty set;
  `[Spf, FlexAlgo(128), FlexAlgo(129)]` → `{0, 128, 129}`.
- `lsdb` ingest test: peer fragment 0 with SR Algorithm sub-TLV
  populates `peer_algos[peer]`; fragment drop clears.

---

### 2. SPF gating skeleton (IGP metric, basic constraints)

**Size:** medium-large (≈400–600 lines).
**Scope:** parameterize the existing legacy / MT graph builder by an
`algo: u8` argument. Per local FAD entry in `flex_algo.config`:

1. Build a filtered graph:
   - Drop peers without `algo` in `peer_algos[sys_id]` (participation
     requirement, RFC 9350 §5.2).
   - For each link, look up `peer_link_affinity[sys_id][neighbor_id]`
     for the peer-advertised affinity bitmap; drop the link if any of
     the FAD's constraints fail:
     - `exclude-any`: drop if intersection with bitmap is non-empty.
     - `include-any`: drop if intersection with bitmap is empty (and
       `include-any` is non-empty).
     - `include-all`: drop if bitmap doesn't cover every required bit.
   - For each link, look up SRLG attached on the peer side; drop the
     link if it intersects FAD `srlg-exclude`. (Note: this needs peer
     SRLG state too — currently we don't cache peer SRLGs. Either add
     `peer_link_srlg` first, or defer SRLG-exclude enforcement to a
     follow-up.)
2. Use IGP metric (the FAD's `metric_type` byte is read but only the
   `igp` value is honored; `min-unidir-link-delay` and `te-default`
   reuse IGP metric for now with a `TODO`).
3. Run Dijkstra (reuse existing `spf::compute`).
4. Store result in:
   - `Isis::graph_flex_algo: Levels<BTreeMap<u8, Option<spf::Graph>>>`
   - `Isis::spf_flex_algo: Levels<BTreeMap<u8, Option<BTreeMap<usize, spf::Path>>>>`

**Files to touch:**
- `zebra-rs/src/isis/graph.rs` — parameterize the graph builder.
- `zebra-rs/src/isis/inst.rs` — add `graph_flex_algo` + `spf_flex_algo`
  fields, thread through `IsisTop`.
- `zebra-rs/src/isis/rib.rs::spf_schedule_top` — invoke per-algo SPF
  alongside the existing legacy / MT runs.
- New module or section in `flex_algo.rs` for the constraint-check
  helpers (`link_passes_fad(affinity, fad) -> bool`).

**Deliberately out of scope:**
- Per-algo RIB install (next PR).
- Non-IGP metric types.
- Per-link SRLG enforcement (needs peer SRLG state cache).
- TI-LFA per flex-algo (the YANG `fast-reroute/ti-lfa` toggle exists
  but no consumer; the existing TI-LFA path is algo-0 only).

**Test plan:**
- Unit tests for the constraint-check helper (matrix of FAD
  include/exclude vs link bitmap → pass/drop).
- Integration test: synthesize a 3-node LSDB with FAD 128 excluding a
  middle link's affinity, assert SPF skips the link.

---

### 3. Per-algo RIB install (SR-MPLS first)

**Size:** medium (≈300–400 lines).
**Scope:** after SPF computes a per-algo `BTreeMap<prefix, Path>`,
install per-algo entries into the IPv4 RIB with an MPLS label stack
derived from `peer_algo_sid[next_hop_sys_id][(algo, prefix)]`. Reuse
the existing `Isis::rib` shape; either add an `algo` key to the RIB
entry or use a separate per-algo RIB map.

**Files to touch:**
- `zebra-rs/src/isis/rib.rs` — extend route entry with `algo: u8`
  (default 0 for legacy SPF), or split into `rib_algo: Levels<BTreeMap<u8, PrefixMap<...>>>`.
- `zebra-rs/src/isis/ilm.rs` — same shape, MPLS label install.
- Per-algo route → kernel: extend the `rib::Message::Ipv4Add` shape
  with an algorithm tag so the RIB-side installer keeps per-algo
  routes distinct.

**Decision required up-front:** does the RIB layer (`zebra-rs/src/rib/`)
key routes by `(prefix, algo)` or only `(prefix)`? Today it's
`(prefix)`. A per-algo extension touches every routing protocol's
install path. Decide whether IS-IS owns per-algo routing in its own
RIB tree (simpler, smaller blast radius) or whether the global RIB
gains an algo dimension (more correct but bigger change).

**Test plan:**
- Compute per-algo SPF in a synthesized topology, assert the right
  MPLS labels reach `rib::Message::Ipv4Add`.

---

### 4. `show isis flex-algo` + `show isis route algorithm N`

**Size:** small-medium (≈300 lines).
**Scope:** operator-visible diagnostics. No protocol changes.

`show isis flex-algo`:
- Configured FADs (`isis.flex_algo.config`): algo, metric-type, priority,
  advertise-definition, dataplane flags, affinity / SRLG constraints,
  ti-lfa flag.
- Per-peer received FADs (`isis.peer_fad`): peer hostname / sys-id,
  per-algo FAD contents.
- Participating algos (local: `sr_algorithms()`; per-peer: `peer_algos`).

`show isis route algorithm N`:
- Reads from the per-algo RIB (after PR #3 above).

**Files to touch:**
- `zebra-rs/src/isis/show.rs` — new `show_flex_algo` rendering, register
  YANG path in `exec.yang`.
- `zebra-rs/yang/exec.yang` — add the show command schemas.

---

### 5. Deferred: per-algo SRv6 Locator emit + parse

**Size:** large, multi-PR. **Status:** deferred from the produce-side
sequence.

**Why deferred:** today's SRv6 locator subscribe machinery
(`Isis::reconcile_locator_watch`) is single-locator only — it watches
one named locator from `IsisConfig::sr_srv6_locator`. Per-algo SRv6
needs:

1. `Isis::watched_flex_algo_locators: BTreeMap<u8, String>` — per-algo
   watched locator names.
2. `Isis::sr_flex_algo_locators: BTreeMap<u8, Locator>` — per-algo
   resolved snapshots populated by `SrRx`.
3. Extension to the reconcile loop to add/remove subscriptions on
   `sr_srv6_flex_algo_locators` config change.
4. Per-algo End SID allocation — new entries in `ElibPool`, separate
   `Isis::sr_flex_algo_end_sid: BTreeMap<u8, Ipv6Addr>` to track
   assignments and de-allocate on locator change.
5. The emit loop itself (small once 1–4 are in place):
   - For each `sr_srv6_flex_algo_locators` entry with both snapshot
     and End SID present, emit `IsisTlvSrv6` with `Srv6Locator { algo:
     FlexAlgo(N), ... }`.

**Suggested PR breakdown:**
- 5a: per-algo locator watch + cache (no emit, no SID alloc).
- 5b: per-algo End SID allocation.
- 5c: per-algo SRv6 Locator TLV 27 emit.
- 5d: parse side — extend `peer_algo_locator` or fold SRv6 locator
  decoding into the existing `srv6_end_map` logic.

**Why this can wait:** SR-MPLS produce + consume is complete; SR-MPLS
flex-algo can be tested end-to-end without SRv6. Deferring SRv6 keeps
the SPF gating + RIB install PRs focused on a single dataplane.

---

### 6. Deferred: IPv6 per-algo Prefix-SID

**Size:** small. **Status:** deferred.

YANG models `interface/ipv4/flex-algo-prefix-sid` only; the symmetric
`ipv6/flex-algo-prefix-sid` is not added. Adding it requires:

1. YANG schema extension under `interface/ipv6` (likely needs a
   sibling `prefix-sid` container first, since today `ipv6` has only
   `enable`).
2. Storage extension on `LinkConfig::ipv6_flex_algo_prefix_sids`.
3. Emit on TLV 236 / 237 IPv6Reach entries.
4. Parse side on the same TLVs.

Wait until IPv6 SR-MPLS use cases materialize; most flex-algo
deployments today are SR-MPLS-over-IPv4 or SRv6.

---

### 7. Deferred: FAD non-IGP metric-types

**Size:** small (codec exists). **Status:** deferred.

The FAD's `metric_type` byte is stored on both produce and consume
sides but `min-unidir-link-delay` (1) and `te-default` (2) are not
wired into SPF input. To enable:

1. Parse delay metric from peer IS-Reach sub-TLVs (RFC 8570 Min
   Unidirectional Link Delay sub-TLV, type 33). Add a per-peer
   `peer_link_delay: Levels<BTreeMap<IsisSysId, BTreeMap<IsisNeighborId, u32>>>` cache.
2. Same for TE default metric (RFC 5305 sub-TLV 18) — already partly
   handled; check whether the existing `IsisSubTeMetric` parse is
   used in graph build.
3. SPF gating: when FAD `metric_type` is delay or te-default, use the
   per-link delay/te value instead of the IGP metric.

Defer until an operator actually needs delay-based flex-algo. The
basic flex-algo (IGP metric, affinity constraints) covers the
majority of deployments.

---

### 8. Deferred: BDD / integration tests for flex-algo

**Size:** medium. **Status:** deferred.

The repo has BDD tests under `bdd/` (excluded from CI per
`zebra-rs-ci-and-merge-rules.md` memory). A flex-algo BDD harness
would:

- Spin up 3+ zebra-rs instances over linux-bridges or netns.
- Exercise `set router isis flex-algo …` config end-to-end.
- Verify per-algo routes appear in the FIB.
- Interop test against FRR / IOS-XR / Nokia if available.

Defer until SPF gating + RIB install have landed and there's
something to integration-test.

## Cross-cutting notes

### Memory model recap

Per-peer caches (`peer_fad`, `peer_link_affinity`, `peer_algo_sid`,
`peer_algos`-to-come) all share the same shape:
`Levels<BTreeMap<IsisSysId, <inner>>>`, populated in
`lsdb::rebuild_sys_state`, threaded through `IsisTop` / `LinkTop` /
`SysStateRefs`. New caches must update **10 construction sites in
lsdb.rs** (2 production + 8 test) plus the field declarations on
`Isis` / `IsisTop` / `LinkTop` / `SysStateRefs`. The pattern is
mechanical but tedious — when in doubt, grep for `peer_algo_sid` and
add the new field next to it everywhere.

### Wire-format completeness

Produce side, SR-MPLS dataplane:
- ✅ FAD sub-TLV (PR #610)
- ✅ SR Algorithm participation (PR #612)
- ✅ Per-link ASLA Extended Admin Group (PR #613)
- ✅ Per-algo Prefix-SID (PR #614)
- ❌ Per-algo Prefix Metric M-flag honoring on receive (codec parses
  the M-flag but no consumer reads it)

Produce side, SRv6 dataplane:
- ❌ Per-algo SRv6 Locator TLV 27 (deferred — see section 5)
- ❌ Per-algo SRv6 End SID (deferred)

Consume side:
- ✅ FAD parse (PR #615)
- ✅ Per-link ASLA parse (PR #616)
- ✅ Per-algo Prefix-SID parse (PR #619)
- ❌ SR Algorithm participation cache (section 1)
- ❌ Per-link delay metric parse (deferred — section 7)
- ❌ Per-link SRLG parse (needed for FAD SRLG-exclude enforcement)

### Module layout

Where new code should land:

- Wire codec → `crates/isis-packet/src/sub/cap.rs` (Router Capability
  sub-TLVs) or `neigh.rs` (IS-reach sub-TLVs) or `prefix.rs`
  (IP-reach sub-TLVs).
- Pure-data helpers (parse/build/check) → `zebra-rs/src/isis/flex_algo.rs`.
- Per-peer caches → `Isis::peer_*` in `inst.rs`, populated in
  `lsdb::rebuild_sys_state`.
- SPF graph filtering → `graph.rs` (new algo parameter).
- SPF result storage → `Isis::spf_flex_algo` / `Isis::graph_flex_algo` in `inst.rs`.
- RIB / ILM install → `rib.rs`.
- Show commands → `show.rs` + `exec.yang`.

### Style references

For each new feature, the closest existing precedent:
- New per-peer cache → mirror `peer_algo_sid` (PR #619) end-to-end.
- New per-link sub-TLV emit → mirror `build_link_asla` (PR #613).
- New per-link sub-TLV parse → mirror `parse_asla_flex_algo_bitmap`
  (PR #616).
- New per-FAD sub-TLV emit → mirror `build_fad_subs` (PR #610).
