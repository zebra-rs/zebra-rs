# BGP Link-State (BGP-LS, RFC 9552) — Implementation Recap

Status: **all 7 phases merged (2026-05-30 / 05-31).** The feature works
end-to-end — a running IS-IS instance translates its LSDB to BGP-LS
(NLRIs + the BGP-LS Attribute) on every SPF convergence, stores it in the
BGP Loc-RIB, and exposes it via `show bgp link-state`.

This memo is the at-a-glance summary. The full design rationale lives in
[`bgp-link-state-plan.md`](bgp-link-state-plan.md); the Phase 3 redo
handoff (now historical) is in
[`bgp-link-state-phase3-status.md`](bgp-link-state-phase3-status.md).

## What BGP-LS does here

AFI **16388** / SAFI **71** (non-VPN). Distributes the IGP link-state
topology into BGP toward a controller / PCE / topology collector. Two
roles, both implemented:

- **Consumer** (receive + store + show): negotiate the capability, parse
  Link-State NLRIs + the BGP-LS Attribute off the wire, keep them in an
  exact-match Loc-RIB, render them.
- **Producer** (the headline goal): the IS-IS task walks its own LSDB,
  translates TLVs → BGP-LS objects, and pushes them to BGP over a channel.
  **IS-IS is the only IGP wired today;** OSPFv2/v3 producers (Protocol-IDs
  3/6) are future work — the codec and RIB are protocol-agnostic.

## Phase-by-phase (all merged)

| Phase | PR | Merge commit | What landed |
|-------|----|--------------|-------------|
| 1  | #1064 | d6db84d3 | Link-State NLRI codec (`crates/bgp-packet/src/attrs/nlri_bgpls.rs`) — Node/Link/IPv4-Prefix/IPv6-Prefix + descriptor TLVs/sub-TLVs, `LsProtocolId`, parse/emit, round-trip tests |
| 2  | #1067 | dfb1ed08 | BGP-LS Attribute codec (path attribute type 29, `attrs/bgpls_attr.rs`) — preserved TLV list so unknown codepoints round-trip |
| 3  | #1071 | 45c3426c | AFI/SAFI plumbing — `Afi::LinkState=16388`/`Safi::LinkState=71`, MP_REACH/MP_UNREACH `LinkState` branches, `Attr::BgpLs` → `BgpAttr.bgp_ls`, MP capability negotiation, `afi-safi link-state` config |
| 4  | #1078 | 1adc1a29 | Receive-side Loc-RIB — `LocalRibBgpLsTable` (cands/selected, single best path), `AdjRibBgpLsTable`, `route_bgpls_update`/`withdraw`, dispatch in `route_from_peer` |
| 5  | #1079 | 654bf3b3 | `show bgp link-state` + `fmt::Display` for `BgpLsNlri`/descriptors; `(LinkState,LinkState)` arm in `show bgp summary` counts |
| 6a | #1080 | e98a4ccf | Producer translation — `isis/bgp_ls.rs::lsp_to_objects(level, lsp)`; pure, unit-tested, zero behavior change |
| 6b | #1083 | 5f5d7134 | Producer wiring — IS-IS→BGP channel, `Message::BgpLs{add,withdraw}`, `route_bgpls_originate`, `SpfDone` hook, diff/withdraw |
| 7  | #1085 | 2de6fd70 | Producer attribute enrichment — BGP-LS Attribute (type 29) per object |

## How the producer works (key design points)

- **Lives in the IS-IS task.** No shared LSDB; IS-IS translates its own
  TLVs to `bgp_packet::BgpLsNlri` + `BgpLsAttr` and pushes add/withdraw to
  BGP over a `tokio` channel (mirrors the `bfd_client_tx` precedent on
  `Isis`). BGP never parses IS-IS TLVs.
- **Channel wiring** (`config/manager.rs` `bgp_tx` cell + `will_set_bgp`
  pre-spawn-BGP-before-IS-IS in `commit_config`; `Isis.bgp_tx` captured
  by value at spawn). The sender is `None` until BGP exists.
- **Trigger = `SpfDone`** (LSDB settled). `isis/bgp_ls.rs::produce` walks
  both levels, builds the current `BTreeMap<BgpLsNlri, BgpLsAttr>`, diffs
  against `Isis.bgp_ls_advertised`, and `try_send`s only the deltas. A
  diff on the **map** (not just the key set) means a metric/admin-group
  change re-advertises — RFC 9552 §5.2 withdraw-old-on-change for free.
- **Storage as Originated.** `route_bgpls_originate` builds an
  `Originated` `BgpRib` keyed by `ORIGINATED_PEER` and inserts straight
  into `local_rib.bgp_ls` (the receive path's peer lookup can't take a
  synthetic ident). The BGP-LS Attribute rides on `bgp_attr.bgp_ls`.

## TLV → BGP-LS mapping (producer)

- fragment-0, non-pseudonode LSP → **Node NLRI** (local System-ID).
- TLV 22 / 222 (Ext/MT IS Reachability) → **Link NLRI** + interface/
  neighbor address descriptors; Link Attribute = IGP metric (1095),
  admin-group (1088), TE default metric (1092) when present.
- TLV 135 / 235 (Ext/MT IPv4) → **IPv4 Prefix NLRI** + prefix metric (1155).
- TLV 236 / 237 (IPv6 / MT IPv6) → **IPv6 Prefix NLRI** + prefix metric.
- Protocol-ID from the level: IS-IS L1 = 1, L2 = 2.

## Key code anchors

- AFI/SAFI: `crates/bgp-packet/src/afi.rs`
- NLRI codec: `crates/bgp-packet/src/attrs/nlri_bgpls.rs`
- Attribute codec: `crates/bgp-packet/src/attrs/bgpls_attr.rs`
- MP dispatch: `crates/bgp-packet/src/attrs/mp_reach.rs` / `mp_unreach.rs`
- Loc-RIB + receive/originate: `zebra-rs/src/bgp/route.rs`
  (`LocalRibBgpLsTable`, `route_bgpls_*`)
- BGP inbox: `zebra-rs/src/bgp/inst.rs` (`Message::BgpLs`, `process_msg`)
- Producer: `zebra-rs/src/isis/bgp_ls.rs` (`lsp_to_objects`, `produce`)
- IS-IS event hook: `zebra-rs/src/isis/inst.rs` (`bgp_ls_produce` on `SpfDone`)
- Show: `zebra-rs/src/bgp/show.rs` (`show_bgp_link_state`)
- Channel spawn wiring: `config/manager.rs`, `config/bgp.rs`, `config/isis.rs`

## Deferred follow-ups (none blocking; in priority-ish order)

1. **Re-advertise the `bgp_ls` Loc-RIB to BGP peers** (iBGP / route
   reflector). Today objects are received/produced/stored/shown but not
   forwarded on to other BGP speakers — the collector-distribution leg.
2. **Two-way link connectivity check** before emitting a Link NLRI (both
   endpoints must advertise the adjacency). Links are advertised one-way now.
3. **Attribute completeness**: max-link-bandwidth (1089–1091, needs an
   IS-IS link sub-TLV variant that isn't parsed yet), Adjacency-SID (1099)
   / SRLG (1096), node SR-Capabilities (1034) / SR-Algorithm (1035),
   Prefix-SID (1158), SRv6 End.X.
4. **OSPFv2 / OSPFv3 producers** (Protocol-IDs 3 / 6).
5. **BGP-LS-VPN** (SAFI 72) + the 8-octet RD NLRI prefix.
6. **FIB install** — N/A for BGP-LS (it's topology, not forwarding state);
   listed only to note it is intentionally out of scope.

## Known limitations

- **Cross-commit spawn order**: if `router bgp` is committed in a *later*
  commit than `router isis`, the IS-IS task captured `bgp_tx = None` at
  spawn and the producer stays dark until restart. Same by-value-capture
  limitation as `bfd_client_tx`. Single-commit configs are fine
  (`commit_config` pre-spawns BGP before IS-IS via `will_set_bgp`).
- **No FRR/IOS-XR interop validation yet** — control-plane is unit-tested
  and CI-green, but not validated against another implementation on the wire.
