# IS-IS IPv4/IPv6 Generics — Status & Remaining Items

Last updated: 2026-06-12 (after PRs #1417, #1419, #1422).

The IS-IS v4/v6 unification effort is **substantially complete**. The
core data path (`build_rib_from_spf<F>`), the show renderers, the LSP
TLV machinery, and the link/neighbor address handling are all either
generic over the `IsisRibFamily` / `IsisRibFamilyShow` traits or
collapsed to a single code path. What remains is a short list of
duplication that is **deliberately not unified** because the two
families genuinely diverge there, plus a few **one-family-only**
functions that will mint a v6 twin the day their missing feature
lands.

---

## Completed

### Original generics pass (Items 1–12, branch `isis-ipv4-ipv6-generics`)

| # | What | Files |
|---|------|-------|
| 1–4 | `SpfRoute<F>`, `SpfNexthop<F>`, `make_rib_entry<F>`, `diff_apply<F>`, `DiffResult<F>` | `rib.rs` |
| 5 | `ReachMap<E>` generic + `ReachMapV4`/`ReachMapV6` aliases | `graph.rs`, `inst.rs`, `lsdb.rs`, `link.rs` |
| 6 | `summarize_frr<F>` (adds `backup_sr_len` to `IsisRibFamily`) | `show.rs`, `rib.rs` |
| 7 | `write_rib_detail<F>` | `show.rs` |
| 8 | `write_rib_table<F>` + `IsisRibFamilyShow` trait | `show.rs` |
| 9 | `write_isis_nhop_detail<F>` | `show.rs` |
| 10 | `build_rib_from_spf<F>` — the central SPF→RIB loop, generic over family + MT-2 mode (trait methods `nhop_addrs`, `reach_entries`, `resolve_sid`, `build_repair`) | `rib.rs:836` |
| 11 | `ip_reach(net: IpNet)` (was `ipv4_reach`/`ipv6_reach`) | `bgp_ls.rs:54` |
| 12 | `prefix_object(…, net: IpNet, …)` (was `ipv4_prefix_object`/`ipv6_prefix_object`) | `bgp_ls.rs:125` |

### Dedup pass (PRs #1417 / #1419 / #1422, 2026-06-12)

| PR | What | Files |
|----|------|-------|
| #1417 | `SplittableTlv` trait + `split_tlv_entries` (one shard-at-255 routine for TLV 135/236/222/237); `push_if_addr_tlvs` shared by LAN + P2P Hello; `ipv6_capable_set` shared between rib and show | `lsp.rs`, `ifsm.rs`, `rib.rs`, `show.rs` |
| #1419 | `write_spf_tree<F>` / `spf_tree_json<F>` / `collect_repair_rows_family<F>` — SPF-tree + repair-list renderers generic over `IsisRibFamilyShow` (new methods `spf_capable_set`, `reach_entries_show`, `spf_prefix_type`, `FAMILY`, `rib`, `backup_*`) | `show.rs` |
| #1422 | Dropped dead `NeighborAddr6.label` → `addr6` is now `BTreeSet<Ipv6Addr>`, struct deleted; `ext_ip_reach_entry`/`ipv6_reach_entry` builders + `collect_redist_entries<P,R,E>` generic for the network/redistribute loops; `addr_add`/`addr_del` merged into `addr_update` + `addr_list_update` | `packet.rs`, `neigh.rs`, `inst.rs`, `lsp.rs`, `link.rs` |

---

## Deliberately NOT unified

These are duplications that the scan surfaced but which should be left
as-is. Forcing a shared abstraction here would obscure intent or hide
genuinely different logic behind a misleading "shared" name.

### TI-LFA repair builders — `build_repair_path_mpls` / `build_repair_path_srv6`

**File:** `tilfa.rs:72` / `tilfa.rs:124`

Only the tail (~30 lines: first-hop link lookup, pseudonode handling,
neighbor-address pick) is shared; the heart is fundamentally
different. MPLS resolves a **flat label stack** via
`repair_segments_to_mpls_labels`; SRv6 walks each segment building a
**CSID carrier-packed** SID list (`NodeSid`→End, `AdjSid`→End.X,
`pack_carriers`). The `Backup` associated type already abstracts the
*output* (`RepairPathMpls` vs `RepairPathSrv6`) at the
`IsisRibFamily::build_repair` boundary, which is the right seam.
A shared first-hop-address helper parameterized by the neighbor
accessor (`addr4.keys().next()` vs `addr6l.first()`) is the only
worthwhile extraction, and it is marginal.

### Backup-detail show writers — `write_isis_backup_v4_detail` / `..._v6_detail`

**File:** `show.rs`

Already dispatched per family via `IsisRibFamilyShow::write_backup`.
The bodies look similar but the content genuinely differs: v4 renders
an MPLS label stack and resolves the P-node from the first label's
SRGB owner; v6 renders an SRv6 SID list plus encap type. No shared
abstraction to add.

### Graph builders — `graph` / `graph_mt2` / `graph_flex_algo`

**File:** `graph.rs:108` / `275` / `548` (+ `create_graph_vertex_mt2`,
`process_outgoing_links_mt2`)

These are **topology variants, not address families**. The near-
identical edge-walking differs by TLV filter (TLV 22 `ExtIsReach` vs
TLV 222 `MtIsReach`), MT-2 membership gating (RFC 5120, IPv6-unicast-
only), and per-link affinity/metric gates (flex-algo). A
visitor/filter parameterization is possible but would bury the
RFC 5120 intent and sits on the SPF-critical hot path — high
regression risk for low payoff. Leave separate.

### `lsp_generate` connected-prefix loop (v4 only path)

**File:** `lsp.rs` (the v4 connected loop, ~`lsp.rs:1058`)

The `network`-statement and redistribute loops are now shared via
`ext_ip_reach_entry`/`ipv6_reach_entry` + `collect_redist_entries`
(PR #1422). The **connected** loops were left per-family because the
v4 one interleaves Prefix-SID and per-algo flex-algo sub-TLVs into the
reach entry, which the v6 path has no analogue for (yet). Unifying
would mean threading sub-TLV builders through a generic, for a single
caller each.

### Neighbor address display loops

**File:** `neigh.rs` (detail show)

Three short `writeln!` loops with different section headers. Below the
threshold where abstraction pays.

---

## Future duplication risk (one-family-only today)

These functions are IPv4-only because the corresponding v6 feature is
not implemented. They are fine as-is, but when the v6 twin lands the
implementer should put them on a trait rather than copy-paste a second
~50–115-line function. Each is flagged here so that's a conscious
choice.

| Function | File | Blocked on |
|----------|------|------------|
| `build_rib_from_flex_algo` | `rib.rs:1504` | Flex-Algo IPv6 (re-implements the core of `build_rib_from_spf` without the trait — **biggest** risk) |
| `update_self_sid_ilm` | `rib.rs:1653` | IPv6 Prefix-SID (SRv6) |
| `build_adjacency_ilm` | `rib.rs:775` | SRv6 Adjacency-SID (Adj-SID is MPLS-only today) |

When any of these gains a v6 counterpart, extend `IsisRibFamily`
(or a sibling trait) with the family-specific accessor it needs —
`V6::resolve_sid` already returns `(None, None, false)` as the
placeholder seam for the Prefix-SID case.

---

## Summary

The generic data path and renderers are done. No further unification
work is recommended on the current feature set: the remaining
duplication is either intrinsic (different algorithms / topologies) or
gated on features that don't exist yet. The doc above is the record of
*why* each remaining seam was left, so a future pass doesn't mistake
it for unfinished work.
