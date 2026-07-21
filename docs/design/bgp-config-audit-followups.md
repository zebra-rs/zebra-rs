# BGP config audits — verification recap & follow-ups

Snapshot as of `main` = `6cfb5b97` (2026-07-21), right after PR #2047
regenerated `docs/schema-paths.txt`, `docs/handler-paths.txt` and
`docs/orphan-report.txt`. The regenerated content was verified
independently before merge; this memo records how (so the next audit
doesn't re-derive the method) and the follow-up slices that came out of
the review, ordered by value.

## How the audits were verified (re-derivable method)

There is no generator in the repo; both lists were rebuilt from scratch
and diffed against the docs:

- **Handler paths**: extract every `callback_add` / `pcallback_add` /
  `callback_peer` / `timer` registration across `zebra-rs/src/bgp/`
  (multi-line calls included; `callback_peer` prepends
  `/router/bgp/neighbor`, `timer` prepends
  `/router/bgp/neighbor/timers`). Result: 223 unique paths,
  set-identical to `handler-paths.txt`. The file is sorted with
  **locale collation** (`LC_ALL=en_US.UTF-8 sort`), not byte order —
  that is why `neighbor-group` sorts after the `neighbor/*` block.
- **Schema paths**: load mode `configure` from `zebra-rs/yang/` with
  `YangStore::read_with_resolve` + `identity_resolve` + `to_entry`
  (exactly the `ConfigManager::init` path, see
  `load_mode` in `zebra-rs/src/config/manager.rs`), walk
  `set → router → bgp`, print `path<TAB>kind` where kind is
  `leaf` / `leaf-list` / `container` / `p-container` /
  `list keys=<keys>`. Convention: list-key leaves are **omitted**
  (implied by `keys=`). Result: 307 nodes, set-identical with matching
  kinds.
- **Orphan report**: settable = every node whose kind ≠ plain
  `container` (275). Handled = has a handler at the exact path, or
  lies under `/router/bgp/tracing` or `/router/bgp/neighbor/tracing`
  (whole-subtree dispatch via `config_tracing_dispatch`,
  `zebra-rs/src/bgp/tracing.rs`). Reproduces 275 / 262 / 3 and the
  10-entry bare-node list exactly.

## Follow-ups

### 1. Drift gate: regenerate-and-compare in `cargo test`

The audits drifted for months because nothing regenerates them. The
cheapest robust gate is a `yang_load_tests`-style unit test
(`zebra-rs/src/config/manager.rs`) that rebuilds both lists in-memory —
schema via `YangStore`/`to_entry` as above, handler paths from
`Bgp::callback_build` — and diffs them against `docs/*.txt`. That runs
inside the existing `cargo test` CI job; no new workflow. Precondition:
item 2, or the test must compare **as sorted sets** (recommended
anyway: switch both files to a deterministic sort when the gate lands,
one-time churn).

### 2. libyang: deterministic `to_entry` child order

`to_entry` child order is **nondeterministic between runs** — two
consecutive dumps of the same tree differ (augment injection order
varies, presumably HashMap iteration in the store). Consequences: no
schema dump is byte-reproducible, `schema-paths.txt` ordering is
arbitrary, and PR #2047's diff was inflated by purely-moved blocks.
Fix upstream in libyang (zebra-rs/libyang): stabilize augment
injection order (sort by module name, or preserve import-closure
order). Benefits every consumer, and makes item 1 byte-exact.

### 3. Orphan report: stale section under-counted (DONE, this branch)

The "Handler paths with no schema node" section listed 12 entries but
the true count by its own definition is 15: `/community-list`,
`/community-list/seq`, `/community-list/seq/action` — registered in
`Bgp::callback_build` (`zebra-rs/src/bgp/config.rs`,
`config_com_list*`), listed at the top of `handler-paths.txt`, but with
no schema node anywhere in the loaded configure tree (searched the full
~1500-node tree, not just `/router/bgp`). Fixed in this branch:
entries + note added to `docs/orphan-report.txt`.

### 4. Decide the fate of the community-list handlers

They are dead registrations today — unreachable, since no YANG surface
defines `community-list`. Either wire a schema (it is a standard
routing-policy primitive; check overlap with the existing
`community-set` under `set` before adding a second spelling) or delete
the three registrations and their `config_com_list*` callbacks.

### 5. Triage the remaining stale handlers with product decisions

- `soft-reconfiguration/inbound`: schema node was removed, handler
  kept. Restore the knob or drop the handler.
- `neighbor/flowspec/validation`: handler exists but
  `zebra-bgp-flowspec.yang` is never imported by `config.yang`. Import
  it when flowspec (SAFI 133 plan, `docs/design/bgp-flowspec-plan.md`)
  lands, or remove the handler until then.
- The lua / loc-rib-hook / adj-rib-out-hook entries are fine as-is:
  explicitly parked with the `lua` feature (commented import in
  `zebra-rs/yang/config.yang`).

### 6. (Longer-term) Real semantics for `neighbor <X> enabled`

Currently accepted-and-inert (kept so IETF/OpenConfig-style configs
load; a neighbor is enabled by configuring `remote-as`). Wiring
`enabled false` to an admin-shutdown of the peer would turn the orphan
into a feature both FRR and OpenConfig have.
