# BGP EVPN Assisted Replication & Pruned-Flood-Lists (RFC 9574) — Design & Phasing Plan

Tracks the implementation of RFC 9574 ("Optimized Ingress Replication
Solution for Ethernet VPN") for zebra-rs: **Assisted Replication (AR)** and
**Pruned-Flood-Lists (P-FL)** on top of the existing EVPN-VXLAN BUM
(Broadcast / Unknown-unicast / Multicast) ingress-replication path. This
document is the living plan + status — it captures the kernel-feasibility
analysis that bounds the scope, the RFC signaling surface, how it maps onto
the current zebra-rs EVPN dataplane, the phase-by-phase slice, and **what
has landed vs what's left** so a contributor can resume without the
conversation history.

Read this first if you're touching `crates/bgp-packet/src/attrs/pmsi_tunnel.rs`,
the EVPN Type-3 IMET origination/reception in `zebra-rs/src/bgp/route.rs`
(`evpn_originate_imet`, the IMET → `MdbAdd` reception path), the BUM
flood-list netlink path in `zebra-rs/src/fib/netlink/handle.rs`
(`mdb_add`/`mdb_del`), `rib::Message::MdbAdd/MdbDel`, or
`zebra-rs/yang/zebra-bgp-evpn.yang`.

## Status (updated 2026-06-20)

Branch `bgp-evpn-bum`. **Phase 0 (codec) landed on the branch**; Phases 1–3
(control plane + the kernel-supported dataplane subset) are planned; Phase 4
(AR-REPLICATOR forwarding) is an explicit out-of-stock-kernel deferral.

| Slice            | What landed / planned                                                                                  | Status |
| ---------------- | ----------------------------------------------------------------------------------------------------- | ------ |
| 0 — PMSI codec   | tunnel type `0x0A`, `AssistedReplicationType` (T), BM/U/L flag accessors on `PmsiTunnel`, 7 pin tests  | ✅ merged #1476 |
| 1a — role + origination | YANG `assisted-replication` role/AR-IP config; role-aware Type-3 IMET origination (Replicator-AR tunnel `0x0A` / AR-LEAF-flagged Regular-IR); pin tests | ✅ merged #1483 |
| 1b — reception + flood model | per-VNI `EvpnFloodState` on `LocalRib`; classify received IMET (Regular-IR vs Replicator-AR); AR-LEAF flood-list collapse to a single `{AR-IP}` with full-IR fallback | ✅ on branch |
| 2 — Pruned-Flood-Lists | YANG `pruned-flood-list` (BM/U) → set flags in our IMET; honor a received whole-VTEP prune (BM **and** U) by dropping the remote from the flood list; BDD prune scenario | ✅ on branch |
| 3 — selective AR | Replicator `L=1` (config `selective`); AR-LEAF originates a Leaf A-D (Type-11, RFC 9572) keyed on the Replicator-AR route, scoped by an `<replicator-NH>:0` IPv4-address-specific RT; replicator imports the leaf set; BDD asserts the `[11]:` route on the replicator | ✅ on branch |
| 4 — AR-REPLICATOR dataplane | decap-on-AR-IP → re-flood to other VTEPs with split-horizon | ⛔ deferred (needs eBPF/XDP or VPP — see feasibility) |

### Where the pieces live

- **Codec (done):** `crates/bgp-packet/src/attrs/pmsi_tunnel.rs` —
  `PmsiTunnel::TUNNEL_INGRESS_REPLICATION` (6) /
  `TUNNEL_ASSISTED_REPLICATION` (0x0A), `AssistedReplicationType`,
  `ar_type()` / `set_ar_type()` / `with_ar_type()`, `prune_bm()` /
  `prune_unknown()`, `leaf_info_required()`, and the `FLAG_*` masks.
- **IMET originate / withdraw:** `zebra-rs/src/bgp/route.rs`
  `evpn_originate_imet` (~`:11539`), `evpn_withdraw_imet` (~`:11616`); the
  PMSI attribute is stamped at ~`:11562` (currently `flags:0,
  tunnel_type:6`).
- **IMET reception → flood list:** `route.rs` ~`:5683–5702`
  (best-path IMET → `rib::Message::MdbAdd`).
- **BUM dataplane (VXLAN FDB):** `zebra-rs/src/fib/netlink/handle.rs`
  `mdb_add` (~`:2487`) / `mdb_del` (~`:2538`) — emit `bridge fdb add
  00:00:00:00:00:00 dev <vxlan> dst <peer-VTEP> self` with
  `NTF_SELF | NTF_EXT_LEARNED` + `NUD_PERMANENT`.
- **RIB message channel:** `zebra-rs/src/rib/inst.rs` `Message::MdbAdd { vni,
  group, source, ifindex, seq }` / `MdbDel` (~`:248–259`).
- **EVPN ext-communities + RT:** `crates/bgp-packet/src/attrs/ext_com.rs`,
  `ext_com_type.rs`; auto-RT at `route.rs::evpn_route_target` (~`:11659`),
  VXLAN encap at `evpn_encap_vxlan` (~`:11677`).
- **VNI/FDB shadow state:** `zebra-rs/src/bgp/inst.rs`
  `local_vxlans: BTreeMap<u32, IpAddr>` / `local_fdb` (~`:544–562`).
- **Config / YANG:** `zebra-rs/yang/zebra-bgp-evpn.yang` (`advertise-all-vni`
  at ~`:62–75`).

## Can the Linux kernel do it? — feasibility (the crux)

RFC 9574 is an optimization of **ingress replication**, the IP-tunnel BUM
mechanism zebra-rs already drives via the kernel VXLAN driver. The kernel
gives exactly **one flood list per VNI** (the set of all-zeros-MAC FDB
entries), shared *uniformly* by broadcast, multicast and unknown-unicast,
with the outer **source IP fixed** to the VXLAN device's `local` address.
RFC 9574's hard requirements collide with all three of those constraints.

| RFC 9574 capability | Stock Linux | Why |
| ------------------- | ----------- | --- |
| **RNVE** (plain IR) | ✅ already works | Zero-MAC FDB fan-out — what zebra-rs does today. |
| **AR-LEAF** (send one BUM copy to replicator's AR-IP) | ⚠️ works *iff* unknown-unicast flooding is disabled | The leaf's flood list collapses to a single zero-MAC FDB entry `dst = AR-IP`. But the kernel can't honor the RFC's "BM → AR-IP, **unknown-unicast → normal IR**" split: there is one flood list for all BUM. Pointing it solely at AR-IP black-holes unknown-unicast (the replicator delivers U to *local* ACs only). Correct only when U-flooding is off (`bridge link set dev vxlanX flood off`) — the standard EVPN posture. |
| **AR-REPLICATOR** (decap a BUM packet on AR-IP → re-flood to all other VTEPs) | ⛔ **not possible on a stock kernel** | Three independent blockers, below. |
| **P-FL: whole-VTEP prune** (BM=1 *and* U=1) | ✅ works | Just omit/remove that remote's zero-MAC FDB entry — pure control-plane → FDB membership. The high-value common case (a low-end NVE that wants no flooding at all). |
| **P-FL: per-category prune** (BM-only *or* U-only for one remote) | ⛔ not expressible | One flood list per VNI; can't keep a remote for broadcast but drop it for unknown-unicast. The per-device `flood` / `mcast_flood` / `bcast_flood` bridge-port flags are device-wide, not per-remote. |

**Why AR-REPLICATOR is a hard "no" on the stock kernel** — the same class of
gap already documented for the deferred EVPN-SRv6-L2 producer (kernel
`seg6local` has no `End.DT2M` "L2 multicast → replicate" behavior):

1. **No VTEP→VTEP re-flood.** A BUM packet received from a VTEP is
   decapsulated into the bridge, which floods only to *other* bridge ports —
   never back out the ingress port. The VXLAN netdev is both the ingress
   port and the sole overlay egress port, so received BUM reaches local ACs
   only and is *never* re-encapsulated toward other VTEPs. There is no
   "replicator" data path in the kernel.
2. **No per-outer-destination branch.** The driver decaps identically
   whether the outer destination was the AR-IP or the IR-IP; there is no
   hook to say "arrived on AR-IP ⇒ re-flood to tunnels." (The RFC's
   single-IP / VNI-discriminated variant doesn't help — the kernel won't
   branch on VNI to re-flood either.)
3. **No per-copy source-IP rewrite.** VXLAN egress source is the device's
   fixed `local` address, so the RFC's "MAY preserve the originating leaf's
   source IP" (needed for multihomed-ES split-horizon) is impossible — and
   even the mandatory re-origination *is* the re-flood the kernel won't do.

A real AR-REPLICATOR therefore needs a **programmable dataplane**:
**eBPF/XDP/tc** (clone, rewrite outer headers per remote IR-IP, source-VTEP
split-horizon, AR-IP/IR-IP branch) or **VPP** (native L2 flood/replication).
zebra-rs already ships XDP/aya infrastructure (BFD/STAMP offload), so an eBPF
replicator is in reach but is a substantial, separate dataplane track —
hence Phase 4 is deferred, not in this series.

**Net:** the entire **control plane** is implementable and
dataplane-agnostic; on the **stock Linux kernel** a zebra-rs node can be an
**RNVE**, an **AR-LEAF** (U-flooding off), and honor **whole-VTEP P-FL
pruning** — but **acting as the AR-REPLICATOR, and per-category pruning, are
out of stock-kernel scope** and belong to an eBPF/XDP or VPP dataplane.

## Locked decisions (2026-06-20)

| Decision | Choice | Consequence |
| -------- | ------ | ----------- |
| **Scope** | Control plane + the Linux-supported dataplane subset | Full RFC 9574 signaling (AR roles, P-FL, selective mode) + RNVE / AR-LEAF / whole-VTEP-prune on the real kernel. AR-REPLICATOR *forwarding* deferred. |
| **Roles on Linux** | RNVE + AR-LEAF + signaling for all roles | A node can *advertise* REPLICATOR (interop / be consumed by a real replicator) but cannot *forward* as one on a stock kernel. |
| **Replicator dataplane** | Deferred to eBPF/XDP or VPP (Phase 4) | Mirrors the EVPN-SRv6-L2 producer deferral; the control plane is the producer that a future replicator dataplane consumes. |
| **Mode order** | Non-selective first, selective later | Non-selective (Phase 1–2) needs no Leaf A-D / IP-specific-RT codec; selective (Phase 3) is an additive control-plane layer. |
| **Unknown-unicast** | Assume U-flooding suppressed | The AR-LEAF flood-list collapse is correct only under the standard "all MACs in the control plane, U-flood off" posture; documented, not silently broken. |

Branch per phase, smallest-reviewable-PR-first (per project convention).

## RFC surface

| RFC | Role |
| --- | ---- |
| RFC 7432 | EVPN base — Type-3 IMET, ingress replication |
| RFC 8365 | EVPN-over-VXLAN (NVO3) — VNI/RD/RT derivation, the IR baseline AR optimizes |
| RFC 9574 | **Optimized Ingress Replication** — Assisted Replication + Pruned-Flood-Lists (this plan) |
| RFC 9572 | EVPN Multicast/ES routes update — Leaf A-D (Type-1) route used by selective AR |
| RFC 6514 / 7902 | PMSI Tunnel Attribute + its Flags registry (the `L` and `E` bits AR reuses) |

### Roles & identification (RFC 9574 §4)

- **RNVE** — Regular NVE, no AR. T-field = `00`. Plain ingress replication.
- **AR-REPLICATOR** — T-field = `01`. Owns two routable IPs: **IR-IP**
  (standard IR) and **AR-IP** (the assisted-replication trigger). Advertises
  a **Replicator-AR** IMET with next-hop = AR-IP.
- **AR-LEAF** — T-field = `10`. Offloads BUM to a replicator; advertises a
  **Regular-IR** IMET (next-hop = IR-IP) with T = AR-LEAF, and (selective
  mode) a Leaf A-D route.

### PMSI Tunnel Attribute Flags — RFC 9574 §4 Figure 3 (verbatim)

Bits numbered with bit 0 = most significant (IANA PMSI flags registry):

```
   0  1  2  3  4  5  6  7
 +--+--+--+--+--+--+--+--+
 |x |E |x |  T  |BM|U |L |
 +--+--+--+--+--+--+--+--+
```

- `E` = bit 1 (`0x40`), Extension (RFC 7902).
- `T` = bits 3–4 (mask `0x18`), Assisted Replication Type:
  `00`=RNVE, `01`=REPLICATOR (`0x08`), `10`=LEAF (`0x10`), `11`=reserved.
- `BM` = bit 5 (`0x04`), prune from Broadcast/Multicast flood list.
- `U` = bit 6 (`0x02`), prune from unknown-unicast flood list.
- `L` = bit 7 (`0x01`), Leaf Information Required (RFC 6514) — set by a
  selective-mode AR-REPLICATOR to solicit Leaf A-D routes.

Tunnel types: `6` = Ingress Replication (existing), `0x0A` = Assisted
Replication (RFC 9574 §11 IANA). **All values pinned by the Phase 0 tests in
`pmsi_tunnel.rs`.**

### Routes (RFC 9574)

| Route | Type | Tunnel type | Next hop | T | L | Use |
| ----- | ---- | ----------- | -------- | - | - | --- |
| Regular-IR | 3 (IMET) | 6 | IR-IP | 00 / 10 | 0 | standard IR; AR-LEAF identity |
| Replicator-AR | 3 (IMET) | 0x0A | AR-IP | 01 | 0/1 | AR-REPLICATOR capability; `L=1` ⇒ selective |
| Leaf A-D | 1 (EAD) | 0x0A | (IR-IP) | 10 | — | AR-LEAF joins a selective replicator's leaf-set, RT = `AR-IP:0` |

### Assisted Replication forwarding (RFC 9574 §5–6) — for the dataplane

- **AR-LEAF**: BM/broadcast → single copy to the replicator's **AR-IP**
  (non-selective: any replicator; selective: the one chosen replicator);
  unknown-unicast → standard IR to all IR-IPs; fallback to full IR if no
  replicator.
- **AR-REPLICATOR** (non-selective): packet arrives on **AR-IP** ⇒ replicate
  to local ACs + all remote AR-LEAF/RNVE (their IR-IPs) + remote
  AR-REPLICATORs (**their IR-IP**, to stop further replication), excluding
  the source; source IP = own IR-IP (MAY preserve original for ES
  split-horizon). Packet on **IR-IP** ⇒ local ACs only. Skip tunnels flagged
  `BM=1` for BM, `U=1` for unknown.

## Fit against current zebra-rs

| Layer | Status | Anchor |
| ----- | ------ | ------ |
| PMSI Tunnel Attribute codec + AR flags | **done (Phase 0)** | `attrs/pmsi_tunnel.rs` |
| Type-3 IMET originate/receive | **exists** | `bgp/route.rs::evpn_originate_imet` (~`:11539`), reception ~`:5683` |
| BUM flood list = zero-MAC FDB | **exists** (single list/VNI) | `fib/netlink/handle.rs::mdb_add/mdb_del` (~`:2487/2538`) |
| `rib::Message::MdbAdd/MdbDel` | **exists** | `rib/inst.rs` ~`:248–259` |
| EVPN ext-comm + auto RT/encap | **exists**, extend for `AR-IP:0` RT | `attrs/ext_com.rs`, `route.rs::evpn_route_target` ~`:11659` |
| Type-1 EAD NLRI | **parsed, not originated** | `attrs/nlri_evpn.rs::EvpnRouteType::EthernetAd` |
| Per-VNI / per-EVI config | **`advertise-all-vni` only** | `zebra-bgp-evpn.yang` ~`:62` |
| **AR-REPLICATOR re-flood datapath** | **does NOT exist — Phase 4** | nothing in `fib/`; needs eBPF/XDP or VPP |
| **Per-category (BM/U) flood list** | **does NOT exist** | kernel limitation (single flood list/VNI) |

Closest end-to-end template: the **EVPN Type-3/IMET** path itself (originate
→ receive → `MdbAdd` flood list) crossed with the **VPNv6-leak series**
(control-plane-only landing, dataplane deferred).

## Architecture

```
                        ┌─────────────────────────────────────────┐
   wire  ───────────►   │ crates/bgp-packet                        │  Phase 0 ✅
                        │  PmsiTunnel: tunnel 0x0A + T/BM/U/L flags │
                        │  (Phase 3) Leaf A-D NLRI, AR-IP:0 RT      │
                        └───────────────┬─────────────────────────┘
                              PMSI(T/BM/U/L) on Type-3 IMET / Type-1 EAD
                        ┌───────────────▼─────────────────────────┐
                        │ zebra-rs/src/bgp                          │
   IMET originate ──►   │  role-aware Replicator-AR / Regular-IR    │  Phase 1
   IMET receive   ──►   │  per-VNI flood model {role,IR-IP,AR-IP,   │  Phase 1
                        │   BM/U}; pick replicator                  │
   P-FL           ──►   │  originate + honor BM/U (whole-VTEP)      │  Phase 2
   selective AR   ──►   │  L=1 / Leaf A-D / per-replicator leaf-set │  Phase 3
                        └───────────────┬─────────────────────────┘
                          rib::Message::MdbAdd/MdbDel  (flood-list membership)
                        ┌───────────────▼─────────────────────────┐
                        │ zebra-rs/src/fib  (Linux VXLAN FDB)       │
   AR-LEAF / RNVE  ─►   │  zero-MAC FDB: {AR-IP} or {IR-IPs};       │  Phase 1–2
   whole-VTEP prune─►   │  omit pruned remotes                      │
                        └───────────────────────────────────────────┘
                        ┌───────────────────────────────────────────┐
                        │ AR-REPLICATOR re-flood datapath            │  Phase 4 ⛔
                        │  eBPF/XDP clone+rewrite, or VPP            │  (out of
                        │  decap-on-AR-IP → fan-out, split-horizon   │   stock kernel)
                        └───────────────────────────────────────────┘
```

## Phasing

| Phase | Scope | Status |
| ----- | ----- | ------ |
| 0 | Codec: PMSI tunnel 0x0A + `AssistedReplicationType` (T) + BM/U/L accessors + pin tests | ✅ merged #1476 |
| 1a | YANG `assisted-replication` role/AR-IP; role-aware Type-3 IMET origination (Replicator-AR `0x0A` / AR-LEAF-flagged Regular-IR) | ✅ merged #1483 |
| 1b | `EvpnFloodState` per-VNI flood model on `LocalRib`; classify received IMET; AR-LEAF flood-list → single `{AR-IP}`, full-IR fallback (U-flood off) | ✅ on branch |
| 2 | Pruned-Flood-Lists: `pruned-flood-list` config → BM/U flags in our IMET; honor a received whole-VTEP prune (BM **and** U) by dropping the remote; partial (BM-only/U-only) not honored (one kernel flood list/VNI) | ✅ on branch |
| 3 | Selective AR (control plane): `selective` config → `L=1`; route-triggered Leaf A-D (Type-11) origination from the AR-LEAF + `<NH>:0` IPv4-address-specific RT; replicator imports the leaf set (reuses the RFC 9251 Leaf A-D codec) | ✅ on branch |
| 4 | **AR-REPLICATOR forwarding dataplane** (eBPF/XDP or VPP) | ⛔ deferred — out of stock-kernel scope |

Phases 0–3 deliver a standards-compliant, interoperable AR/P-FL **control
plane** plus the genuinely-useful Linux dataplane subset (RNVE, AR-LEAF,
whole-VTEP prune), mirroring how the v6 BGP stack and the Flowspec series
shipped control-plane-first. Phase 4 carries the dataplane risk.

### BDD (`@bgp_evpn_ar`) — ✅ on branch

The repo's first VXLAN-dataplane BDD. Three iBGP (AS 65001) EVPN nodes on a
shared bridge, each with a config-driven local VXLAN (VNI 10) so every node
originates a Type-3 IMET: **z1** = AR-REPLICATOR (`replicator-ip
192.168.0.101`), **z2** = AR-LEAF, **z3** = RNVE. Asserts, against the real
kernel state:

- **Control plane** — `show bgp evpn` on z2/z3 shows all three Type-3 IMET
  routes (auto-RT `65001:10`), confirming the mesh imports each node's IMET.
- **1b flood collapse** — `bridge fdb show dev vxlan10` on **z2** contains a
  single zero-MAC `dst 192.168.0.101` (the AR-IP) and **not** z3's VTEP,
  proving the AR-LEAF collapse; on **z3** it contains both remote IR-IPs
  (`.1`, `.2`) and **not** the AR-IP, proving RNVE full ingress replication.
- **Phase 2 P-FL** — z3 also requests whole-VTEP prune (`pruned-flood-list`
  BM + U); **z1**'s FDB drops z3 (`not contain 192.168.0.3`) while keeping z2,
  proving a received whole-VTEP prune is honored.
- **Phase 3 selective AR** — z1 is a `selective` replicator (L flag); z2
  (leaf) originates a Leaf A-D (Type-11) that z1 imports, asserted as a
  `[11]:[rt3/19B]:[192.168.0.2]` route in z1's `show bgp evpn`.

This verifies the whole 1a→1b chain end-to-end: z1 originates Replicator-AR
(AR-IP in the PMSI tunnel endpoint), z2 classifies it and collapses its flood
list. A new `bridge fdb {dev} in namespace {ns} should [eventually] contain /
not contain {needle}` step was added (mirrors `kernel route …`). Ends with an
explicit `Scenario: Teardown topology` (asserts the environment is clean). The
AR-REPLICATOR *forwarding* path can't be BDD-tested on a stock kernel — noted,
not faked. Run: `cd bdd && cargo test --test cucumber -- --concurrency=1 --tags
"@bgp_evpn_ar"` (needs `make install` first).

## Leftover / deferred

- **Selective AR joins *all* replicators, not one chosen.** The AR-LEAF
  originates a Leaf A-D toward every selective replicator it sees, where
  RFC 9574 has it join a single chosen replicator's set. Harmless with no
  replicator dataplane (Phase 4); chosen-replicator selection + a
  config-change reconcile (the origination is route-triggered today, so a
  role/`selective` flip after routes arrive isn't retro-applied) are
  follow-ups.
- **Replicator-AR BGP next-hop = AR-IP (RFC 9574 §4).** Found via the
  `@bgp_evpn_ar` BDD (confirmed again in Phase 3: the leaf builds the
  `<NH>:0` selective RT from the *received* next-hop, which is the VTEP):
  the EVPN advertise path overrides the route's BGP next-hop to the local
  VTEP, so a Replicator-AR route carries next-hop = VTEP, not the AR-IP. zebra-rs is self-consistent (it reads the AR-IP from
  the PMSI tunnel endpoint, which *is* set correctly), so the flood collapse
  works — but for strict interop with implementations that read the AR-IP
  from the BGP next-hop, the next-hop should be the AR-IP. Fix is in the EVPN
  next-hop emit (next-hop-self override); deferred to keep that change
  focused.
- **Render the PMSI tunnel attribute in `show bgp evpn`.** Today `show bgp
  evpn` prints prefix + next-hop + ext-comms but not the PMSI tunnel
  type/flags, so the AR role isn't observable via `show` (only via the FDB).
  Adding a PMSI line would make AR role / tunnel-type 0x0A operator-visible.
- **Phase 4 — AR-REPLICATOR forwarding.** The decap-on-AR-IP → re-flood
  datapath with source-VTEP split-horizon and (optional) source-IP
  preservation. Needs eBPF/XDP/tc clone+redirect+header-rewrite or a VPP
  southbound; not expressible on the stock kernel VXLAN/bridge datapath.
- **Per-category (BM-only / U-only) P-FL pruning.** Kernel has one flood
  list per VNI; per-remote per-category pruning needs the Phase 4 dataplane.
- **AR-LEAF with unknown-unicast flooding *enabled*.** The RFC's separate
  "U via IR, BM via AR-IP" lists can't be expressed by a single zero-MAC FDB
  flood list; supported only under U-flood-off.
- **Multihomed ES interaction** (local-bias / split-horizon on AR-IP vs
  IR-IP, RFC 9574 §5–6) — control-plane modeling deferred until ES (Type-1/4)
  origination exists.
- **EVPN over MPLS/MPLSoUDP/MPLSoGRE AR** — zebra-rs L2 EVPN is VXLAN-only
  today; AR over other IP tunnels follows the same control plane but no L2
  MPLS dataplane exists.
