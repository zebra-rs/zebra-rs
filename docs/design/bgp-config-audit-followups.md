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
  `/router/bgp/neighbor/timers`). Result: 224 unique paths. **Trap**:
  the extraction pattern must accept the **empty** string literal —
  `callback_peer("", config_peer)` registers the bare
  `/router/bgp/neighbor` path. Both #2047 and its review used a
  one-or-more-chars pattern, missed it, and agreed with each other;
  the drift-gate test caught it (see item 1).
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
  `zebra-rs/src/bgp/tracing.rs`). Correct figures: 275 / 263 / 3
  (#2047 said 262 — it missed the bare-neighbor handler above and
  listed `/router/bgp/neighbor` as an unhandled bare node).

## Follow-ups

### 1. Drift gate: regenerate-and-compare in `cargo test` (DONE, this branch)

The audits drifted for months because nothing regenerates them. Done:
`bgp_config_audit_tests` in `zebra-rs/src/config/manager.rs` rebuilds
both lists in-memory — schema via `YangStore`/`to_entry` as above,
handler paths by scanning the registration call sites under
`src/bgp/` — and compares them **byte-exact** against `docs/*.txt`;
a third test re-derives the orphan-report counts, bare-node section
and stale-handler section. Canonical file order is a plain byte sort
(one-time churn in this branch); regenerate the two path files with
`ZEBRA_UPDATE_AUDIT_DOCS=1 cargo test -p zebra-rs bgp_config_audit`
(the orphan report is prose and stays hand-maintained). The gate paid
for itself immediately: it caught the `callback_peer("")`
bare-neighbor miss in #2047 (and in the review that confirmed it).

### 2. libyang: deterministic `to_entry` child order — root-caused

`to_entry` child order is **nondeterministic between runs**: dumping
the whole `configure` tree (3050 nodes) five times with libyang 1.1.0
from crates.io gives **five different orderings** — same node set every
time, order only. Consequences: no schema dump is byte-reproducible,
`schema-paths.txt` ordering is arbitrary, and PR #2047's diff was
inflated by purely-moved blocks.

Root cause, confirmed: `YangStore::modules` is a
`HashMap<String, ModuleNode>` (`src/store/reader.rs:12`), and
`to_entry` walks it to apply each loaded module's augments
(`for (name, m) in store.modules.iter()`, `src/store/entry.rs:202`).
Rust randomizes `HashMap` iteration per process, so augment injection
order — and therefore the order augmented children land in `dir` —
changes every run. Only two sites iterate the field
(`entry.rs:202`, `reader.rs:51`).

Fix (verified locally against a patched copy): change the field to
`BTreeMap<String, ModuleNode>`, which makes both sites deterministic.
With that one-line change the same five-run test produces a **single**
ordering. Upstream in zebra-rs/libyang, so it needs a release + a
version bump here before it takes effect; `zebra-rs/Cargo.toml` pins
`libyang = "1"`. Benefits every consumer; would also let the audits
keep declaration order instead of item 1's byte sort.

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
