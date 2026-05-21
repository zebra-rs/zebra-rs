# BGP MPLS/VPN — Status, Architecture, Follow-ups

Tracks the refactor that lets zebra-rs run multiple BGP instances
across Linux VRFs and exchange VPNv4 routes per RFC 4364. The
22-step plan that originally drove this work has been delivered;
this document captures **what landed**, **why each slice landed in
the shape it did**, and **what's intentionally deferred** so a
future contributor can resume without reading the conversation
history.

Read this first if you're touching anything under
`zebra-rs/src/bgp/vrf/`, `bgp::tag_attr_with_export_rts`,
`bgp::matching_import_vrfs`, `bgp::vrf::Vrf{Exporter,ImportDispatcher,LabelAllocator}`,
the `RibRx::Vrf*` arms, or the `IlmType::DecapVrf` netlink builder.

## What landed

The original 22-step plan was sliced finer than expected; every
hidden dependency (the route-target callbacks, the per-VRF FSM
refactor, the FIB-layer DecapVrf, the BgpTop dependency
explosion) drove a sub-slice (a/b/c/i/ii/iii) so each PR stayed
under ~800 LOC and reviewable. Final landed set, in commit
order:

| Phase                | PR    | Subject                                           | Slice from original plan                                       |
| -------------------- | ----- | ------------------------------------------------- | -------------------------------------------------------------- |
| 0–1: foundation      | #630  | RibClient + ProtoContext (7 squashed branches)    | Steps 1–7                                                      |
| 2: VRF wiring        | step 8  | `SO_BINDTODEVICE` in `maybe_bind_device`        | Step 8                                                         |
| 2: VRF wiring        | step 9  | RIB inbound dispatch by `ProtoId → vrf_id`      | Step 9                                                         |
| 2: VRF wiring        | step 10 | RIB outbound filter + retire `redists`           | Step 10                                                        |
| 3: YANG + config     | step 11 | `zebra-bgp-vrf.yang` full per-VRF grouping       | Step 11                                                        |
| 3: YANG + config     | step 12 | `BgpVrfConfig` staging                            | Step 12                                                        |
| 4: per-VRF runtime   | step 13 | `BgpVrf` task type                                | Step 13                                                        |
| 4: per-VRF runtime   | step 14 | `spawn_bgp_vrf` / `despawn_bgp_vrf` diff         | Step 14                                                        |
| 4: per-VRF runtime   | step 15a | `ProtoContext::for_vrf` via `VrfAdd` notif       | Step 15 (sliced)                                              |
| 4: per-VRF runtime   | step 15b | Per-VRF `RibClient` subscription                  | Step 15 (sliced)                                              |
| 4: per-VRF runtime   | step 15c | Peer materialization (scaffolding)                | Step 15 (sliced)                                              |
| 4: per-VRF runtime   | step 16  | Accept dispatch global → VRF (`peer_index`)      | Step 16                                                        |
| 4: per-VRF runtime   | step 15d | Per-VRF FSM driver                                | Step 15 (sliced — completed)                                  |
| 5a: route-target     | step 17a | RT YANG callbacks + `RibRx::VrfRouteTargets`     | Hidden dep of step 17 (plan assumed RT config existed)         |
| 5b: export pipeline  | step 17b-i | Export payload + producer + stub handler        | Step 17 (sliced)                                              |
| 5b: export pipeline  | step 17b-ii | Export handler: tag + intern + LocRIB write    | Step 17 (sliced)                                              |
| 5b: export pipeline  | step 17b-iii | Best-path hook in `route_ipv4_update`         | Step 17 (sliced — completes producer side)                    |
| 5c: export flush     | step 17c | Update-group flush to VPNv4 peers                 | Step 17 (sliced — completes wire emit)                        |
| 5d: import pipeline  | step 18a | ImportV4 payload + matching + dispatcher          | Step 18 (sliced)                                              |
| 5d: import pipeline  | step 18b | Per-VRF LocRIB write + CE advertise               | Step 18 (sliced — completes import side)                      |
| 5e: MPLS label       | step 19a | `VrfLabelAllocator` + Export uses real label     | Step 19 (sliced)                                              |
| 5e: MPLS label       | step 19b | `IlmType::DecapVrf` + ILM install at spawn        | Step 19 (sliced — completes data plane)                       |
| 6: observability     | step 20a | `show ip bgp vrf` (list + detail, global state)  | Step 20 (sliced)                                              |
| 6: observability     | step 21a | `bgp_vrf_show` BDD scenario                       | Step 21 (sliced)                                              |
| 6: docs              | step 22 | This refresh                                      | Step 22                                                       |

End-to-end VPN routing is now both control- and data-plane complete:

```
CE_left ─eBGP─ PE_left ─VPNv4─ PE_right ─eBGP─ CE_right
                 ↑                ↑
   step 17b-iii hook    step 18a hook
   step 17b-ii LocRIB    step 18b LocRIB
   step 17c flush        CE advertise via existing
                         route_advertise_to_peers
                                  ↑
       step 19a label allocator + step 19b DecapVrf ILM
                  (kernel pops, lookups in vrf_tables[id])
```

## Architecture

### Cross-task message layout

```
  ┌─────────────────────────┐   BgpGlobalMsg   ┌─────────────────────┐
  │     Bgp (global)        │ ◀──────────────  │   BgpVrf (vrf v1)   │
  │  Loc-RIB v4 + v4vpn     │                  │   Loc-RIB v4 only   │
  │  VPNv4 peers + listen   │  ─────────────▶  │   CE peers          │
  │  VrfLabelAllocator      │   BgpVrfMsg      │   FSM driver        │
  │  rib_known_vrfs         │                  └─────────────────────┘
  │  peer_index             │   (one task per `router bgp vrf X`)
  │  vrf_registry           │
  └─────────────────────────┘
            ▲
            │ RibRx (Vrf{Add,Del,RouteTargets})
            │
  ┌─────────────────────────┐
  │       Rib (global)      │
  │  vrfs (kernel+RT)       │
  │  vrf_tables[table_id]   │   ◀── per-VRF route installs
  │  AF_MPLS ILM            │   ◀── DecapVrf @ vrf.label
  └─────────────────────────┘
```

`BgpGlobalMsg` (per-VRF → global, on `Bgp::vrf_global_rx`):
- `RegisterPeer` / `UnregisterPeer` — populate the global
  `peer_index` for inbound `:179` dispatch.
- `Export { vrf, prefix, attr, label }` — per-VRF best-path
  winner promoted to a VPNv4 candidate.
- `WithdrawExport { vrf, prefix }` — inverse.

`BgpVrfMsg` (global → per-VRF, on each VRF task's `global_rx`):
- `Accept(TcpStream, SocketAddr)` — passive accept routed by
  `peer_index`. (Per-VRF passive accept handler is still
  deferred; see follow-ups.)
- `ImportV4 { rd, prefix, attr, label }` — VPNv4 best-path
  filtered by RT match.
- `WithdrawImport { rd, prefix }` — inverse.
- `Shutdown` — clean task teardown.

### Shared `BgpTop` for the route pipeline

The shared `route_ipv4_update` / `route_ipv4_withdraw` code path
sees both global and per-VRF runtime through a `BgpTop<'a>`
borrow. Two `Option` hooks distinguish the two callers:

- `vrf_export: Option<&VrfExporter>` — `Some` only inside a
  `BgpVrf` task; fires `vrf_emit_export` after best-path runs.
- `vrf_import: Option<&VrfImportDispatcher>` — `Some` only inside
  the global `Bgp` task; fires `dispatch_import_v4` after
  best-path runs on a `rd.is_some()` route.

This split avoids two copies of the recv pipeline — every other
field (`local_rib`, `attr_store`, `update_groups`,
`interface_addrs`, `color_policy`, `flex_algo_routes`) is wired
the same way.

### RT plumbing

Top-level `vrf X { ipv4 { route-target { import/export } } }`
flows:

```
yang/config.yang (top-level vrf list)
  → rib::vrf::VrfBuilder (8 path handlers parsing into BTreeSet<RD>)
  → Message::VrfRouteTargets {ipv4_{import,export}_rts, ipv6_*}
  → Rib::vrfs[name].{ipv4_import_rts, ...}
  → api_vrf_route_targets broadcast
  → RibRx::VrfRouteTargets to default-VRF subscribers
  → Bgp::rib_known_vrfs[name].{import_rts_v4, export_rts_v4, ...}
```

Read by `tag_attr_with_export_rts` (export-side; appends
ExtCommunity sub-type `0x02` per RFC 4360 §4.1) and by
`matching_import_vrfs` (import-side; intersects the route's RT
extcomms with each VRF's `import_rts_v4`).

RT and RD share the on-wire 6-octet shape, so the storage type
reuses `bgp_packet::RouteDistinguisher`. The 4-byte ASN RT
encoding (high_type 0x02) is accepted by the YANG pattern but
not by `RouteDistinguisher::from_str` — the builder rejects it
at commit-time.

### MPLS label lifecycle

`VrfLabelAllocator` lives on `Bgp::vrf_label_alloc`:
- Counter from `FIRST_USABLE_LABEL` (16, per RFC 3032 §2.1).
- Sorted free-list — lowest reclaimed label re-issued first.
- Reserved frees (< 16) silently ignored.

Allocation flow:
- `apply_vrf_commit_diff` spawn arm: `alloc()` → store on
  `BgpVrfHandle::label` and `BgpVrf::label`.
- `maybe_respawn_vrf_with_kernel_ctx`: reuses the existing handle's
  label so the placeholder → real-`for_vrf` swap doesn't disturb
  any PE-side FIB entry pointing at the old label.
- `apply_vrf_commit_diff` despawn arm: send `Message::IlmDel` for
  the AF_MPLS DecapVrf ILM, then `free(label)`.

ILM install (`IlmType::DecapVrf { table_id, vrf_ifindex }`):
the FIB layer emits an AF_MPLS netlink route at `label/20` with
no `NEW_DESTINATION` (pure pop) and `Oif(vrf_ifindex)`. Linux
routes the popped inner packet via the VRF master, which lands
the lookup in the slave table.

## Slicing decisions captured during execution

These are calls made when a planned step turned out larger than
estimated. Recording them here so a future similar move doesn't
re-litigate.

- **17b sliced into i/ii/iii.** The original "Export" step
  bundled payload extension, global handler, and best-path hook.
  Each is independently reviewable; iii closed the loop. The same
  payload shape (`{vrf, prefix, attr, label}`) is reused by 18a.
- **17c split from 17b.** "Update-group flush to VPNv4 peers"
  uses the existing `route_advertise_to_peers` helper; making it
  `pub(super)` was the whole change. Worth its own PR because the
  global `Bgp` had to construct a `BgpTop` for the helper.
- **18a vs 18b.** 18a delivers the message + dispatch; 18b writes
  to the per-VRF LocRIB and advertises to CE peers. The split
  reveals the receive-side LocRIB write isn't symmetric with the
  Export side — the Export side runs `local_rib.update` directly,
  while Import re-uses `local_rib.update(None, prefix, ...)` from
  the per-VRF runtime then calls `route_advertise_to_peers`.
- **19a (allocator) before 19b (FIB).** The label flows through
  `BgpGlobalMsg::Export.label` end-to-end without touching the
  netlink layer. 19b adds `IlmType::DecapVrf` after the control
  plane carries real labels, so the FIB layer change is bounded.
- **17a parsed RT before the export pipeline used it.** The
  original plan assumed the top-level RT config already existed;
  it didn't. 17a wires it as a standalone PR.
- **20a reads only global-side state.** Per-VRF tokio task state
  isn't reachable from `show_bgp_vrf`. A future step 20b would
  push a `BgpGlobalMsg::VrfStatus` snapshot for per-peer detail;
  for now the show callback covers name, RD, label, table_id,
  ifindex, RT sets, neighbor IPs.

## Deferred follow-ups

Land in any order; none block each other.

- **`peer::accept` refactor for VRF passive accept.**
  `peer::accept(bgp: &mut Bgp, ...)` is tied to the global runtime.
  Step 16 routes the `TcpStream` to the matching VRF via
  `BgpVrfMsg::Accept`, but the per-VRF handler currently drops
  the stream — there's no `BgpVrf::accept` mirror. A refactor to
  take a trait or the BgpTop accessor would let both global and
  VRF tasks share the body.
- **Per-VRF YANG callbacks via `BgpVrf::cm`.** Today every
  `/router/bgp/vrf/X/...` commit lands on the global `Bgp`'s
  `cm` channel, which writes `BgpVrfConfig`, then step 14
  respawns the VRF task to pick up the changes. A per-peer
  edit (e.g. `set router bgp vrf X neighbor 10.0.0.1 enabled
  false`) shouldn't require a respawn; future work routes the
  per-peer callbacks straight to `BgpVrf::cm`.
- **v6 import/export symmetry.** `BgpVrfMsg::ImportV6` and
  `BgpGlobalMsg::Export` IPv6 variants are placeholders. The
  shape mirrors v4; just hasn't been wired.
- **ND / BFD per-VRF.** The per-VRF `BgpVrf` carries an empty
  `InterfaceAddrs` because BGP unnumbered (interface-neighbor)
  and BFD client hand-off live on the global `Bgp`. Per-VRF
  unnumbered peering and per-VRF BFD subscriptions would need
  the per-VRF task to hold its own ND / BFD client handles.
- **Per-VRF snapshot mirroring (step 20b).** `show ip bgp vrf
  NAME` currently doesn't show per-peer FSM state. A snapshot
  via `BgpGlobalMsg::VrfStatus` would unlock that.
- **`clear bgp vrf` action.** Not yet wired. Operator currently
  has to delete + re-add the VRF config to bounce sessions.
- **End-to-end multi-PE BDD (step 21b/c).** `bgp_vrf_show`
  exercises the local commit→`show` path; a two-PE topology
  with a gobgpd CE simulator and VPNv4 wire-level assertions
  is still future work.
- **4-byte ASN RT encoding.** YANG accepts it; the Rust parser
  in `bgp_packet::RouteDistinguisher::from_str` doesn't.
  Builder rejects at commit. Fix is in `bgp_packet`.

## Key design decisions (carried forward)

- **`ConfigManager::next_proto_id` is `Arc<AtomicU32>`.** Was
  `Cell<u32>` originally; converted in step 15b so the allocator
  could be cloned into tokio tasks. `RibSubscriber`
  bundles `rib_tx` + `rib_inbound_tx` + the atomic so per-VRF
  spawn sites can mint subscriptions from `!Send` ConfigManager
  context.
- **Per-VRF `BgpAttrStore` / `UpdateGroupMap`.** Step 15d gives
  each per-VRF runtime its own attribute dedup pool and
  update-group machinery rather than sharing across the
  `!Send` boundary. Cross-task `BgpAttr` transfer happens
  through the `Export` / `Import` messages by value; the global
  side re-interns into its own store.
- **VRF-originated routes use `ident == 0, local_id == 0`.** The
  Export handler stamps these onto the `BgpRib` it writes;
  WithdrawExport finds the row by the same tuple. Real CE
  peers always have non-zero `ident` (allocated by `PeerMap`),
  so no collision.
- **Label reuse on respawn.** When `maybe_respawn_vrf_with_kernel_ctx`
  swaps the placeholder ctx for the real one, it reuses the
  existing label. Otherwise a brief outage would invalidate
  PE-side FIB entries.
- **Step 8 design decisions still apply.** ConfigManager owns
  `ProtoId` allocation, one subscriber = one VRF, `ProtoContext`
  bundles `RibClient` + VRF info, `maybe_bind_device` is the
  single VRF-aware site in the transport layer, BFD uses
  `default_table_no_rib()`. See the original list at the bottom
  of this file before the refresh for full rationale.

## Branch chain history (phase 0 + 1)

The seven step-by-step branches that built the foundation were
squashed before merge as PR #630. Names kept here so historical
conversation pointers still resolve:

```
main
└── rib-client                       (step 1)
    └── rib-client-migrate           (step 2)
        └── rib-client-consolidate   (step 3)
            └── proto-context        (step 4)
                └── bgp-proto-context    (step 5)
                    └── protos-proto-context (step 6)
                        └── rib-vrf-tables   (step 7, squash-merged as #630)
```

Phases 2 through 6 (PRs from step 8 through this refresh) were
each merged as a single non-squash PR — the per-step narrative
is the merge log on `main`. `git log --first-parent main` walks
them in order.
