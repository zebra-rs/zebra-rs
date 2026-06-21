# BGP EVPN BUM over SR P2MP Replication (RFC 9524) — Design & Phasing Plan

Tracks the implementation of **RFC 9524 "Segment Routing Replication for
Multipoint Service Delivery"** as an EVPN BUM (Broadcast / Unknown-unicast /
Multicast) tunnel, on top of the existing EVPN-VXLAN ingress-replication and
RFC 9574 Assisted-Replication paths. This document is the living plan + status:
the spec split, the kernel-feasibility analysis that bounds the scope, the
signaling surface, how it maps onto the current zebra-rs EVPN dataplane, the
phase-by-phase slice with **what has landed vs what's left**, and the eBPF
dataplane design — so a contributor can resume without the conversation
history.

Read this first if you're touching `crates/bgp-packet/src/attrs/pmsi_tunnel.rs`,
the EVPN Type-3 IMET origination/reception + `EvpnFloodState` in
`zebra-rs/src/bgp/route.rs`, the `bum-tunnel-type` config in
`zebra-rs/src/bgp/config.rs` / `zebra-rs/yang/zebra-bgp-evpn.yang`,
`rib::Message::ReplSegAdd/ReplSegDel` in `zebra-rs/src/rib/inst.rs`, or the
`offload/tc-evpn-replicate/` eBPF crate.

## The spec split (read this first)

RFC 9524 is **not** an EVPN document — it defines a **data-plane** construct,
the **Replication segment**:

- **SR-MPLS:** a replication node POPs the incoming replication label, then for
  each downstream branch PUSHes that branch's replication label (+ optional
  segment list) onto a *copy* of the packet.
- **SRv6:** a new **`End.Replicate`** behavior — replicate, rewrite the IPv6 DA
  to each downstream Replication-SID, optionally `H.Encaps.Red` a segment list.
- "**Replication segmentation**" = stitching segments into a P2MP *tree* (Root
  → bud → Leaf) so no single node fans out to all leaves and transit nodes hold
  no per-flow state.

How EVPN *uses* it is a separate spec, **`draft-ietf-bess-mvpn-evpn-sr-p2mp`**:
the binding rides in the **PMSI Tunnel attribute** (RFC 6514, attr 22) on the
EVPN **Type-3 IMET** route, using new PMSI tunnel types for SR P2MP trees. The
replication segment itself is instantiated by a controller (PCEP/BGP/NETCONF) —
explicitly out of RFC 9524's scope; zebra-rs computes the degenerate
ingress-rooted tree locally (see Phase CP3).

## Kernel-feasibility analysis (bounds the scope)

**The stock Linux kernel cannot forward an RFC 9524 replication tree.** Verified
against current kernel sources:

| RFC 9524 role | needs | native Linux? |
|---|---|---|
| **Root** (ingress PE) | replicate one BUM frame into N SR-encapsulated copies | ❌ for SR (`mpls_route` is ECMP not P2MP; `seg6` encap emits one copy). Only **VXLAN head-end** replication is native. |
| **Replication / bud** | `End.Replicate` (SRv6) or replication-label POP→PUSH-to-many (SR-MPLS) | ❌ `seg6_local.h` has **no `End.Replicate`**; no MPLS P2MP. This is the capability that *defines* RFC 9524. |
| **Leaf** (egress PE) | decap + flood into the BD: SRv6 `End.DT2M`, or MPLS→bridge-flood | ❌ no `End.DT2M`/`DT2U` (only `End.DX2`, point-to-point). ✅ only for VXLAN. |

The only EVPN-BUM path the kernel does natively is **VXLAN head-end ingress
replication** (the degenerate single-segment case, over VXLAN/IP) — which
doesn't need RFC 9524. The kernel-friendly cousin **RFC 9574 Assisted
Replication** (replicator VTEP) reduces fan-out *within* native VXLAN and is
already implemented (see `bgp-evpn-assisted-replication-plan.md`).

**Decision:** to actually forward RFC 9524 on Linux, build a dedicated **eBPF
TC/clsact** dataplane (`offload/tc-evpn-replicate/`). TC, not XDP, because each
downstream branch needs an independently-rewritten copy
(`bpf_clone_redirect` in a loop, mutating the skb between clones); XDP has no
per-copy clone. (VPP / smartNIC are the alternative external dataplanes.)

## Signaling surface

PMSI Tunnel attribute (IANA "PMSI Tunnel Types"):

| Tunnel | PMSI type | Tunnel identifier |
|---|---|---|
| Ingress Replication | `0x06` | originating PE IP |
| Assisted Replication (RFC 9574) | `0x0A` | AR-IP |
| **SR-MPLS P2MP Tree** | `0x0C` | **Tree-ID (4) + Root IP** |
| **SRv6 P2MP Tree** | `0x0D` | **Tree-ID (4) + Root IP** |

The MPLS-label field is 0 for SR P2MP unless the tunnel is shared (SR-MPLS
upstream label / DCB) or SRv6 transposition is used (deferred). The Root is the
originating PE's VTEP; the Tree-ID (derived from the VNI) uniquely identifies an
SR P2MP policy at the Root.

## How it maps onto the zebra-rs EVPN dataplane

- **Config:** `router bgp afi-safi evpn bum-tunnel-type
  {ingress-replication|sr-mpls-p2mp|srv6-p2mp}` selects the inclusive BUM tunnel
  (`EvpnBumTunnel` enum). Default ingress-replication; SR modes bypass the AR
  role.
- **Origination:** `evpn_originate_imet` records the local VTEP as the VNI's
  tree Root (`EvpnFloodState::set_local_root`) and emits the SR P2MP PMSI.
- **Reception:** an SR P2MP IMET is recorded in a per-VNI `sr_remotes` map
  (mutually exclusive with the IR/AR `remotes` map) and **excluded** from the
  VXLAN head-end flood (`desired()` empties in SR mode) — its BUM rides the
  tree, not a zero-MAC FDB entry.
- **Producer → dataplane:** `reconcile` computes the tree's leaf set
  (`replication_leaves` = every remote PE) and, via the pure delta-tracked
  `replication_action`, sends `rib::Message::ReplSegAdd { vni, tree_id, root,
  srv6, leaves }` / `ReplSegDel { vni }`. The RIB consumes it (today a stub
  log) and will drive the eBPF replication map.

## Phasing & status (updated 2026-06-18)

Branch `bgp-evpn-tunnel-replication`. The **control plane is complete and
merged**, and the SRv6 **`End.Replicate`** datapath (clone + per-branch outer-DA
rewrite) is **implemented and lab-validated**. The remaining gap is the leaf
`End.DT2M` decap (strip outer IPv6+SRH, redirect inner to the bridge).

| Slice | What landed / planned | Status |
| --- | --- | --- |
| CP1 — PMSI codepoints | `TUNNEL_SR_MPLS_P2MP` (0x0C) / `TUNNEL_SRV6_P2MP` (0x0D) + `is_sr_p2mp()` | ✅ merged #1487 |
| CP2a — PMSI identifier codec | `PmsiTunnel.tree_id`; parse/emit Tree-ID + Root; `PmsiTunnel::sr_p2mp()` | ✅ merged #1491 |
| CP2b — origination | `bum-tunnel-type` knob (`EvpnBumTunnel`); `imet_pmsi_tunnel` emits the SR P2MP PMSI (Root = VTEP, Tree-ID = VNI) | ✅ merged #1494 |
| CP2b — import | record SR P2MP IMET (Root, Tree-ID) in `sr_remotes`; exclude from VXLAN flood; mutual-exclusivity + `sr_p2mp_remotes()` seam | ✅ merged #1498 |
| CP3 — flood suppression + leaf model | `desired()` empty in SR mode (withdraws stale VXLAN IR); `replication_leaves()` | ✅ merged #1500 |
| DP1 — eBPF skeleton | `offload/tc-evpn-replicate/` (loader+ebpf, TC/clsact `#[classifier]`, no-op); build-verified | ✅ merged #1505 |
| DP1 — ReplSeg handoff | `Message::ReplSegAdd/ReplSegDel` + producer (`set_local_root`/`replication_action`) + FIB stub consumer; mode-change reconcile | ✅ merged #1508 |
| DP2 — supervisor | spawn/refcount the `tc-evpn-replicate` loader child (pattern: `bfd/reflector.rs`), feed it over stdin line-IPC from the `ReplSeg` consumer | ✅ merged #1518 |
| DP3a — BPF map + loader | `REPL_SEG` map + loader `repl-add`/`repl-del` population (clone+rewrite logic still a no-op) | ✅ merged #1520 |
| DP3b — `End.Replicate` | clsact-ingress clone loop: match outer DA against `REPL_LOCAL_SID`, decrement Hop Limit (guard ≤1), `clone_redirect` one copy per leaf with outer DA rewritten, drop original. Lab-validated (`scripts/veth-replicate-test.sh`) | ✅ this slice |
| DP3c — leaf `End.DT2M` | match the local `End.DT2M` SID → strip outer IPv6+SRH, redirect inner frame to the bridge master for native BUM flooding | ⬜ planned |

## Where the pieces live

- **Codec:** `crates/bgp-packet/src/attrs/pmsi_tunnel.rs` —
  `TUNNEL_SR_MPLS_P2MP`/`TUNNEL_SRV6_P2MP`, `is_sr_p2mp()`, `tree_id`,
  `PmsiTunnel::sr_p2mp()`.
- **Config / state:** `EvpnBumTunnel` in `zebra-rs/src/bgp/inst.rs`;
  `config_evpn_bum_tunnel_type` in `config.rs`; `bum-tunnel-type` leaf in
  `zebra-rs/yang/zebra-bgp-evpn.yang`.
- **Origination / reception / producer:** `zebra-rs/src/bgp/route.rs` —
  `EvpnFloodState` (`bum_tunnel`, `sr_remotes`, `root`, `repl_installed`),
  `set_local_root`/`clear_local_root`, `replication_leaves`,
  `replication_action`/`ReplAction`, `reconcile`, `evpn_originate_imet`.
- **RIB handoff:** `rib::Message::ReplSegAdd/ReplSegDel` +
  `process_msg` consumer in `zebra-rs/src/rib/inst.rs` (stub).
- **Dataplane:** `offload/tc-evpn-replicate/` (workspace-excluded; nightly +
  bpf-linker; **CI does not build it**).
- **User docs:** the "SR P2MP replication trees" section of
  `book/src/ch-02-33-bgp-evpn-assisted-replication.md`. The sibling
  AR-REPLICATOR eBPF/VPP dataplane effort is tracked in
  `bgp-evpn-ar-replicator-dataplane-plan.md` (same offload approach).

## eBPF dataplane design (DP2/DP3)

- New `offload/tc-evpn-replicate/` crate mirrors `offload/xdp-bfd-echo/` but a
  TC/clsact `#[classifier]`. Roles, all clsact-attached: **root/bud** (ingress)
  match the Replication-SID → clone + per-branch outer-DA rewrite
  (`End.Replicate`, **implemented**); **leaf** (ingress) match the `End.DT2M`
  SID → strip outer IPv6+SRH, redirect inner frame to the bridge master for
  native BUM flooding (DP3c). A root that must `H.Encaps` a bare BUM frame
  (rather than re-replicate an already-encapsulated one) is a later refinement.
- **Maps** (loader-filled): `REPL_SEG` (per-VNI segment: tree-id, leaf SIDs);
  `REPL_LOCAL_SID` (local replication SID → VNI, so the datapath demuxes an
  inbound packet to its segment by outer IPv6 DA — derived here from each
  segment's root SID); `CONFIG[0]` (egress ifindex the copies leave on,
  `--redirect-iface`). Fed from `ReplSeg` over a stdin line protocol; a
  supervisor spawns/refcounts the loader per ifindex.
- **`End.Replicate` datapath:** on an inbound IPv6 frame whose outer DA hits
  `REPL_LOCAL_SID`, decrement the outer Hop Limit (drop if ≤1), then for each
  leaf rewrite the outer DA and `clone_redirect` a copy out `CONFIG[0]`; drop
  the original (`TC_ACT_SHOT`). Writes use `bpf_skb_store_bytes`/`load_bytes`
  (not raw `data` pointers), so nothing is held across the `clone_redirect`s
  that invalidate packet pointers. No outer checksum fix-up is needed (IPv6 has
  no header checksum; the outer DA is not in any inner L4 pseudo-header).
  Validated end-to-end on a veth pair by `scripts/veth-replicate-test.sh` (one
  frame to a replication SID → a copy at each leaf SID).
- **Caveats:** `bpf_clone_redirect` is TC-only; the leaf decap (DP3c) and any
  SRH segment-list rewrite are still to come; `H.Encaps.Red` MTU (eBPF can't
  fragment → jumbo/large underlay); veth needs the clsact path (no native XDP);
  aya is pulled from git unpinned.

## Gotchas / build notes

- `Cargo.lock` is **gitignored**; `netlink-packet-route` is a `seg6` *branch*
  dep — after a rebase onto a main that bumped it, local builds fail in
  untouched netlink files (e.g. `MdbGroup`) while CI is green; fix with
  `cargo update -p netlink-packet-route@0.20.1` (not `cargo fetch`).
- `main` moves fast in the EVPN area — expect to rebase each PR over neighbor
  EVPN work (IGMP/MLD proxy, SMET dataplane, RFC 9572 segmentation,
  pruned-flood-list).

## Out of scope / deferred

- SR P2MP **tunnel-identifier** label transposition (SR-MPLS upstream label /
  SRv6 Function transposition) — label field left 0.
- Controller-instantiated replication SIDs (PCEP / BGP SR-P2MP policy) — only
  the locally-computed degenerate tree is built.
- Multi-tier (bud-node) replication forwarding depends on the eBPF dataplane
  (DP3); the signaling/state model already supports it.
