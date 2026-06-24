# BGP EVPN IGMP/MLD Proxy (RFC 9251) — Design & Phasing Plan

Tracks the implementation of EVPN IGMP/MLD Proxy support for zebra-rs:
the new EVPN route types **6 (Selective Multicast Ethernet Tag / SMET)**,
7 (Multicast Join Synch), and 8 (Multicast Leave Synch), plus the
**Multicast Flags Extended Community**. This document is the living plan +
status: it captures the RFC surface, the wire formats, the current state
of the codebase, the architecture decisions, the phase-by-phase slice, and
**what has landed vs what's left** so a contributor can resume without the
conversation history.

Read this first if you're touching `crates/bgp-packet/src/attrs/nlri_evpn.rs`,
`ext_com.rs` / `ext_com_type.rs`, the `MpReachAttr::Evpn` arm in
`mp_reach.rs`, the `LocalRib.evpn` tables / `bgp::route::evpn_*` paths,
the `rib::Message::Mdb*` / `fib/netlink/handle.rs` MDB code, or
`zebra-rs/yang/zebra-bgp-evpn.yang`.

Branch: `bgp-evpn-igmp-mld-proxy` (already created).

## Status (updated 2026-06-20) — COMPLETE

**All six phases are merged to `main` and validated live** (the
`@bgp_evpn_smet` BDD passes 5/5 against real kernel namespaces). Type-6
SMET works end to end for single-homed PEs: a kernel-bridge IGMP/MLD
snoop drives SMET origination, a received SMET imports into the Loc-RIB
and programs the kernel bridge MDB, and the Multicast Flags EC signals
proxy capability on the Type-3 IMET. Type 7/8 (multihoming synch) and
true per-VTEP `dst` selectivity are deferred (see **Deferred**).

| Phase | Slice                                   | State    | PR    |
| ----- | --------------------------------------- | -------- | ----- |
| 0     | Design doc (this file)                  | **done** | #1477 |
| 1     | Codec — Type 6 SMET NLRI                | **done** | #1486 |
| 2     | Multicast Flags Extended Community      | **done** | #1489 |
| 3     | IMET (Type 3) capability signaling      | **done** | #1493 |
| 4     | SMET origination from kernel MDB snoop  | **done** | #1502 |
| 5     | SMET reception → selective dataplane    | **done** | #1506 |
| 6     | Show + BDD + docs                       | **done** | #1510 |
| —     | Type 7/8 codec + control-plane stub     | **done** | —     |
| —     | Type 7/8 multihoming data plane (DF/ES) | deferred | —     |

(Phase 4 also pushed `netlink-packet-route` `seg6` commit `d912564`, which
adds the MDB-entry decode; tracked via the `branch = "seg6"` dependency.)

### One-paragraph recap

Wire types live in `crates/bgp-packet`: `EvpnSmet` / `EvpnRoute::Smet` /
`EvpnPrefix::Smet` (`nlri_evpn.rs`) and `EvpnMcastFlags` (`ext_com.rs`,
type 0x06 / sub 0x09). The data path is fib → rib → bgp: kernel
`RTM_NEWMDB` (joined group `RTNLGRP_MDB`, plus an `RTM_GETMDB` startup
dump) → `FibMessage::NewMdb` → rib maps bridge→VNI (`mdb_vni_vtep`) →
`RibRx::SnoopJoin` → `bgp::route::evpn_originate_smet` (RD `router-id:VNI`,
RT `AS:VNI`, next hop = local VTEP, Flags via `smet_flags()`). On receive,
`route_evpn_export_selected` → `rib::Message::SmetInstall` →
`fib::mdb_install` (an `MDBA_SET_ENTRY`; NESTED `MDBE_ATTR_SOURCE` for
`(S,G)`). The `igmp-mld-proxy` knob (`zebra-bgp-evpn.yang`) gates
origination and the IMET capability EC. User docs:
`book/src/ch-02-32-bgp-evpn-igmp-mld-proxy.md`.

## Locked decisions (2026-06-20, with Kunihiro)

| Decision              | Choice                                       | Consequence |
| --------------------- | -------------------------------------------- | ----------- |
| **Scope**             | Type 6 (SMET) only, single-homed             | Type 7/8 Join/Leave synch deferred — they need Ethernet-Segment (Type 1 EAD + Type 4 ES) + DF election, neither of which exists in the tree |
| **Membership source** | Kernel bridge MDB snooping (`RTM_*MDB`)      | The Linux bridge does the IGMP/MLD snooping/querier; zebra-rs reads local membership over netlink and bridges it to/from BGP (the FRR model). No IGMP/MLD packet engine is built in zebra-rs |
| **Dataplane**         | Real kernel bridge MDB, control-plane first  | Selective forwarding = `bridge mdb add grp G dst <VTEP>` (distinct from the Type-3 zero-MAC-FDB *flood* list). Codec/EC/origination land before the selective install |
| **Address families**  | IPv4/IGMP **and** IPv6/MLD                    | Flags field and src/grp encodings cover both from the start |

Branch per phase, smallest-reviewable-PR-first (per project convention),
`cargo fmt` + workspace clippy + BDD-with-teardown each PR.

## RFC surface

| RFC      | Role                                                                              |
| -------- | -------------------------------------------------------------------------------- |
| RFC 9251 | IGMP/MLD Proxies for EVPN — defines Route Types 6/7/8 and the Multicast Flags EC |
| RFC 7432 | Base EVPN (RD, ESI, Ethernet Tag, route-type framing, RT import)                 |
| RFC 6514 | PMSI Tunnel attribute (Ingress Replication) — already used on Type-3 IMET        |
| RFC 7606 | Revised error handling — "treat-as-withdraw" for malformed Type-6 NLRI/flags     |
| RFC 8365 | NVO/VXLAN EVPN data plane (RT/encap ext-comm conventions already in the tree)    |

## Wire formats (RFC 9251)

### Route Type 6 — Selective Multicast Ethernet Tag (SMET)

| Field                    | Length      | Notes                                            |
| ------------------------ | ----------- | ------------------------------------------------ |
| RD                       | 8           | Type 1 recommended                               |
| Ethernet Tag ID          | 4           |                                                  |
| Multicast Source Length  | 1           | bits: 0 = `*`, 32 = IPv4, 128 = IPv6             |
| Multicast Source Address | 0 / 4 / 16  | absent when length = 0 (`*,G`)                    |
| Multicast Group Length   | 1           | bits: 32 = IPv4, 128 = IPv6                       |
| Multicast Group Address  | 4 / 16      |                                                  |
| Originator Router Length | 1           | bits                                             |
| Originator Router Address| 4 / 16      |                                                  |
| Flags                    | 1           | version + IE bits — **NOT part of the route key**|

**Flags octet** (bit 7 = LSB): bit0-3 reserved, **bit4 IE** (0=include,
1=exclude), **bit5 v3**, **bit6 v2**, **bit7 v1**. For IGMP the sender
MUST set v1=0; for MLD there is no v3 (bit5 MUST be 0), v2=MLDv2,
v1=MLDv1.

### Multicast Flags Extended Community (Type 0x06, Sub-Type 0x09)

```
 0      1       2 3       4 5 6 7
+------+-------+-----+-----------+
| 0x06 | 0x09  |Flags| Reserved  |
|      |       |(2)  |   (4)     |
+------+-------+-----+-----------+
```
Flags (2 octets): **bit 15 = IGMP Proxy Support**, **bit 14 = MLD Proxy
Support**, bits 0-13 reserved. Both-zero ⇒ malformed, ignore the EC.
Rides on the Type-3 IMET route to advertise proxy capability.

### Route Types 7 / 8 (codec + control-plane stub implemented)

Type 7 (Join Synch) = SMET fields **plus a 10-octet ESI** (after RD,
before Ethernet Tag). Type 8 (Leave Synch) = Type 7 fields **plus**
Reserved(4) + Maximum Response Time(1) before Flags. Both MUST carry an
**ES-Import RT** and **exactly one EVI-RT EC** (`0x06` / sub-types
`0x0A`–`0x0D` for the 2-octet-AS / IPv4 / 4-octet-AS / IPv6 RT shapes).
Distribution is scoped by the ES-Import RT only; the EVI-RT EC carries the
EVI's RT value but does not control propagation.

The NLRI codec, the ES-Import RT / EVI-RT extended communities, the EVPN
RIB store + reflect path, the `show bgp evpn igmp-join-sync` /
`igmp-leave-sync` filters, and the origination helpers are now in tree;
the multihoming data plane (DF election, Ethernet-Segment Type 1/4, the
synch state machine, and the ES-snoop origination trigger) remains
deferred. See `bgp-evpn-igmp-mld-proxy-followups.md` §6 for the full
breakdown.

## Operational model (how SMET fits with Type 3)

- Today an EVPN PE floods BUM (incl. multicast) to **every** remote VTEP
  in the Type-3 (IMET) ingress-replication list.
- With IGMP/MLD proxy: the local Linux bridge snoops membership. For each
  local `(*,G)` / `(S,G)` join, the PE originates a **Type-6 SMET** route
  (RT = the EVI RT, i.e. per-VNI). On leave it withdraws the SMET.
- An ingress PE then replicates `(x,G)` traffic **only** to egress PEs that
  (a) advertised the Multicast Flags EC on their IMET *and* (b) advertised
  a matching SMET — others fall back to flood. On Linux this selective
  state is the **kernel bridge MDB** (`bridge mdb add … grp G dst <VTEP>`),
  not the zero-MAC FDB flood list.
- Origination triggers (RFC 9251 §6): first report for a `(*,G)`; any
  IGMPv3 `(S,G)`; a version upgrade ⇒ **re-advertise** (set both version
  flags), never withdraw-then-add.

## Current state of the codebase (survey 2026-06-20)

### Codec — `crates/bgp-packet/src/attrs/nlri_evpn.rs`
- `EvpnRouteType` (≈L14) names types 1-5 + `Unknown(u8)`; both `From`
  impls (≈L24, L38) round-trip the route-type byte. **Only 2/3/5 are
  parsed/emitted**; 1 and 4 error out.
- `EvpnRoute` (≈L60) = `{Mac, Multicast, Prefix}`. RD-stripped RIB key
  `EvpnPrefix` (≈L118) = `{MacIp, InclusiveMulticast, IpPrefix}`, with
  `route_type()` (≈L144) and `from_route()` (≈L154). Variant order is kept
  so the derived `Ord` yields 2→3→5 in `show` output.
- `parse_nlri` (≈L223) and `nlri_emit` (≈L343) dispatch on the route-type
  byte. The Type-3 path already implements the **length-in-bits → variable
  IP** idiom that SMET's src/grp/originator fields need.
- `MpReachAttr::Evpn` parses NLRIs via `EvpnRoute::parse_nlri` in a
  `many0_complete` loop (`mp_reach.rs` ≈L435).

### Extended communities — `ext_com_type.rs` / `ext_com.rs`
- `ExtCommunityType` defines `TransTwoOctetAS=0x00`, `TransOpaque=0x03`,
  `Mup=0x0c`. **No `0x06` (EVPN) type, no Multicast Flags EC, no EVI-RT
  EC, no ES-Import RT.** RT helper + VXLAN encap EC exist.

### RIB / processing — `zebra-rs/src/bgp/route.rs`
- `LocalRib.evpn: BTreeMap<RouteDistinguisher, LocalRibEvpnTable>`, each
  keyed by `EvpnPrefix` (cands + selected; best-path via `is_better`).
- Originators: `evpn_originate_macip` (≈L11278), `evpn_originate_imet`
  (≈L11539, attaches the PMSI Tunnel / Ingress-Replication attr),
  `evpn_originate_type5` (≈L11436).
- Import: `route_evpn_export_selected` (≈L5579) emits `rib::Message::MacAdd`
  (Type-2) / `rib::Message::MdbAdd` (Type-3). RT→VRF matching via
  `import_targets` (`inst.rs` ≈L308) against `RibKnownVrf`.
- Config gate: `config_advertise_all_vni` (`config.rs` ≈L1334) on
  `advertise-all-vni` (`zebra-bgp-evpn.yang`).
- Show: `show_bgp_evpn` (`show.rs` ≈L3097), `format_evpn_ecom_value`
  (≈L3066).

### Dataplane — `zebra-rs/src/fib/netlink/handle.rs` (the important gap)
- `rib::Message::{MdbAdd, MdbDel}` (`rib/inst.rs` ≈L248) → `mdb_add` /
  `mdb_del` (`handle.rs` ≈L2487). **Misnamed**: these do NOT touch the
  kernel MDB — they install a **zero-MAC FDB** row (`dst = peer VTEP`,
  `NLM_F_APPEND`) for Type-3 BUM ingress replication (the *flood* list).
- Reading local snooped membership (`RTM_NEWMDB`) is an explicit TODO
  (`handle.rs` ≈L2930).
- There is **no IGMP/MLD snooping engine and no local-membership source**
  anywhere in the tree.

### netlink fork (good news — groundwork partly exists)
- zebra-rs pins `netlink-packet-route = { git = ".../zebra-rs/netlink-packet-route",
  branch = "seg6" }` and a forked `rtnetlink`. Local checkouts:
  `../netlink-packet-route`, `../rtnetlink`.
- The `seg6` fork (HEAD `8773fb8`) **already** wires MDB at the message
  level: `RTM_NEWMDB/DELMDB/GETMDB` → `RouteNetlinkMessage::{NewMdb,
  DelMdb, GetMdb}`, with `MdbMessage` / `MdbAttribute` (`src/mdb/`).
  **But** `MDBA_MDB` / `MDBA_MROUTE` payloads are kept as raw `Vec<u8>` —
  the inner `br_mdb_entry` (ifindex/state/flags/vid) + nested
  `MDBA_MDB_ENTRY_INFO` + `MDBE_ATTR_SOURCE/GROUP` codec is **not done**.
  Phases 4a / 5a complete this and bump the Cargo rev.

## Phase-by-phase slice

### Phase 0 — Design doc — **done**
This file. Branch already created.

### Phase 1 — Codec: Type 6 SMET NLRI — **done**
`crates/bgp-packet/src/attrs/nlri_evpn.rs`
- Added `EvpnRouteType::SmetRoute => 6` (both `From` impls).
- New `EvpnSmet { id, rd, ether_tag, src: Option<IpAddr>, grp, orig,
  flags: u8 }`; `EvpnRoute::Smet`; parse (`parse_len_prefixed_ip`
  helper) + emit (`emit_len_prefixed_ip` helper) arms reusing the
  length-in-bits IP idiom (src length 0 ⇒ `*`).
- `EvpnPrefix::Smet { eth_tag, src, grp, orig }` — **flags excluded
  from the key** (RFC 9251); `route_type()`→6, `from_route()`, `Display`
  (`[6]:[EthTag]:[SrcLen]:[Src]:[GrpLen]:[Grp]:[OrigLen]:[Orig]`),
  `Ord` order 2→3→5→6.
- 8 round-trip / wire-layout tests: `(*,G)` v4, `(S,G)` v4, `(*,G)`
  v6/MLD, add-path, bad-group-length rejection (RFC 7606 treat-as-
  withdraw at the caller).
- Compile-through arms on the shared enums: `MpReach`/`MpUnreach`
  `Display`; `route.rs` advertise/withdraw reconstruction, peer-down
  `build_evpn_route`, `evpn_route_type_of`, `evpn_vni_of` (SMET VNI from
  the EVI RT, like Type-3), `route_evpn_export_selected` (no-op — the
  selective MDB dataplane is Phase 5), and the id accessors.
- Policy: `policy::EvpnRouteType::Smet` (+ `smet` YANG enum) so
  `match evpn route-type smet` parses.

**Phase 1 limitation (resolved in Phase 4):** SMET Flags are not in the
RIB key, and `BgpRib` does not yet carry them, so a *re-advertised*
(reflected) SMET emits `flags = 0` (`TODO(phase4)`). Received SMET is
parsed, stored in the Loc-RIB, and renderable; no SMET origination or
dataplane action happens yet.

### Phase 2 — Multicast Flags Extended Community — **done**
`crates/bgp-packet/src/attrs/ext_com_type.rs`, `ext_com.rs`
- Added `ExtCommunityType::Evpn = 0x06`; the Multicast Flags sub-type
  is the module const `EVPN_MCAST_FLAGS_SUB_TYPE = 0x09`.
- `EvpnMcastFlags { igmp_proxy, mld_proxy }` with `From<…> for
  ExtCommunityValue` (2-octet flags: bit15=IGMP `0x0001`, bit14=MLD
  `0x0002`; 4-octet reserved), `ExtCommunityValue::is_evpn_mcast_flags`
  / `as_evpn_mcast_flags` (the latter returns `None` when both bits
  clear, per §6 "ignore"), and a `Display` branch rendering
  `mcast-flags:IM`. Both types re-exported via `pub use ext_com::*`.
- 6 unit tests: wire layout, IGMP-only round-trip, both-zero ignored,
  `Display`, not-matching-for-RT, emit→parse round-trip.

### Phase 3 — IMET (Type 3) capability signaling — **done**
`zebra-rs/src/bgp/inst.rs`, `route.rs`, `config.rs`,
`zebra-rs/yang/zebra-bgp-evpn.yang`, `config/manager.rs`
- New config knob `router bgp afi-safi evpn igmp-mld-proxy <bool>`
  (`zebra-bgp-evpn.yang` leaf → `Bgp::igmp_mld_proxy`,
  `config_igmp_mld_proxy`). Toggling re-originates all IMET via
  `reoriginate_all_imet`.
- `evpn_originate_imet` attaches the Multicast Flags EC
  (`EvpnMcastFlags { igmp_proxy: true, mld_proxy: true }`) to the IMET
  route's extended communities when the knob is on.
- YANG-load `*_is_settable` test for the new leaf.
- **Consumer read folded into Phase 5:** the capability rides the IMET
  path attr and is already in the Loc-RIB; Phase 5 reads it on demand
  via the Phase-2 `ExtCommunityValue::as_evpn_mcast_flags` accessor when
  deciding selective-vs-flood. A receiving PE already renders
  `mcast-flags:IM` in `show bgp evpn` (Phase-2 `Display`), so the signal
  is observable end-to-end today. Per-protocol (IGMP-only / MLD-only)
  granularity is a follow-up.

### Phase 4 — SMET origination from kernel MDB snoop — **done**
- **4a (fork `netlink-packet-route` `seg6`):** `src/mdb/entry.rs` decodes
  the nested `MDBA_MDB → MDBA_MDB_ENTRY → MDBA_MDB_ENTRY_INFO →
  br_mdb_entry + MDBA_MDB_EATTR_SOURCE` tree into typed
  `MdbEntry { port_ifindex, state, flags, vid, group, source }` (+
  `MdbGroup`, `parse_mdb_entries`, `MdbMessage::entries()`). Pushed to
  `seg6` (commit `d912564`); Cargo.lock bumped to it.
- **4b (fib):** join `RTNLGRP_MDB` (group 26); `process_msg` handles
  `NewMdb/DelMdb` → `mdb_entries_from_msg` (IP groups only) →
  `FibMessage::NewMdb/DelMdb { bridge_ifindex, vid, group, source }`;
  `mdb_dump` issues an `RTM_GETMDB` dump at startup via
  `Handle::request`. RIB `process_fib_msg` maps `bridge_ifindex →
  (VNI, local VTEP)` (`mdb_vni_vtep` over `vni_for_bridge` +
  `vxlan_local_for_bridge`) → `RibRx::SnoopJoin/SnoopLeave`.
- **4c (bgp):** `process_rib_msg` caches membership in `local_smet` and
  calls `evpn_originate_smet` / `evpn_withdraw_smet` (`route.rs`): RD
  auto-derived `router-id:VNI`, RT = EVI RT `AS:VNI`, next hop = local
  VTEP, no PMSI, Flags via `smet_flags()` (IPv4→IGMPv3, IPv6→MLDv2; IE =
  exclude for `(*,G)`, include for `(S,G)`). The Flags octet now rides on
  `BgpRib::smet_flags` (resolves the Phase-1 TODO), so reflected SMET
  preserves it. Gated on the `igmp-mld-proxy` knob; `config_igmp_mld_proxy`
  replays `local_smet` across the gate transition.

**Notes / deferred:** the existing Type-3 `MdbAdd`/`mdb_add` (zero-MAC FDB
flood list) was left as-is rather than renamed — the new SMET path uses
distinct `SnoopJoin/SnoopLeave` messages, so there's no functional
overload; the rename is cosmetic and can come with Phase 5. SMET flags
are a per-family approximation, not derived from the kernel MDB
group-mode (follow-up). No selective dataplane yet (Phase 5).

### Phase 5 — SMET reception → selective dataplane — **done**
- **5a (fib `handle.rs`):** `mdb_install(bridge, port, vid, group, source,
  dst, add)` emits `RTM_{NEW,DEL}MDB` via the fork's `MdbMessage` +
  `MdbAttribute::Other` (no fork change needed). A `(*,G)` entry is the
  bare `MDBA_SET_ENTRY` (`br_mdb_entry`); an `(S,G)` entry adds a
  **NESTED** (`NLA_F_NESTED`) `MDBA_SET_ENTRY_ATTRS` holding
  `MDBE_ATTR_SOURCE`. Byte-layout unit tests. Needed the one-line
  `netlink-packet-utils = "0.5.2"` dep (unifies with the fork's) to name
  `DefaultNla`. **`MDBE_ATTR_DST` is deliberately NOT encoded** — the
  kernel rejects it on a plain VXLAN (EINVAL) and `iproute2` drops it
  too; per-VTEP `dst` selectivity needs a `vnifilter` VXLAN MDB
  (follow-up, found via the Phase-6 BDD).
- **5b (rib):** `rib::Message::SmetInstall/SmetRemove`; `smet_install`
  resolves the VNI to its local `(bridge, vxlan-port)` via
  `vni_to_bridge_vxlan` and calls `mdb_install` (vid 0; per-VLAN is a
  follow-up).
- **5c (bgp `route_evpn_export_selected`):** the Smet arms now send
  `SmetInstall` (best-path, non-Originated, dst = SMET `orig`) /
  `SmetRemove` (withdraw), VNI from the EVI RT.

**No explicit flood reconciliation needed:** a snooping bridge forwards
*registered* groups (those with an MDB entry) only to the MDB dsts and
floods only *unregistered* groups over the Type-3 zero-MAC FDB list — so
installing received SMET as MDB entries yields selective delivery, and a
non-proxy PE (which never sends SMET) keeps getting the flood. The
Multicast Flags EC gate (skip sending selective toward non-proxy PEs) is
therefore an optimization, deferred. **Live forwarding is validated in
Phase 6's BDD** (byte layout is unit-tested here).

### Phase 6 — Show + BDD + docs — **done**
- `show bgp evpn` renders Type-6 via the Phase-1 `EvpnPrefix` `Display`
  (`[6]:[EthTag]:[SrcLen]:[Src]:[GrpLen]:[Grp]:[OrigLen]:[Orig]`); the
  `smet` route-type filter + type-6 legend were already present.
  `format_evpn_ecom_value` now renders the Multicast Flags EC as `MF:IM`.
- BDD `@bgp_evpn_smet` (`bdd/tests/features/bgp_evpn_smet.feature` +
  `configs/bgp_evpn_smet/z{1,2}-1.yaml`): two iBGP EVPN nodes, each with
  a `mcast_snooping` bridge + enslaved VXLAN; a `bridge mdb add` on z2
  drives SMET origination; asserts z1 shows the SMET + `RT:65001:10`,
  z1's kernel bridge MDB gains the group, and a leave withdraws both.
  Plus a new `I execute "<cmd>" in namespace` step (raw `ip`/`bridge`,
  vs the vtyctl-only `I run`) and `bridge mdb … contain` steps. Teardown
  scenario asserts a clean environment. **Ran live (sudo netns): 5/5
  scenarios pass.**
- The BDD found and fixed a real Phase-5 dataplane bug: the original
  `mdb_install` sent `MDBE_ATTR_DST`, which the kernel rejected with
  EINVAL — corrected to the `MDBA_SET_ENTRY`-only / NESTED-source form
  above.

## Deferred (not built — recorded so a contributor can pick it up)

> The deferred items are written up with code anchors and an approach
> for each in **`bgp-evpn-igmp-mld-proxy-followups.md`** (per-VTEP `dst`
> via vnifilter VXLAN MDB; link-local-group filtering; SMET-flags
> fidelity; the MF-EC capability gate; per-VLAN VID; Type 7/8). The
> headline below stays here for quick reference.

**Type 7 / 8 (Multicast Join / Leave Synch).** All-active multihoming
only. Prerequisites absent today:
- Ethernet-Segment support: Type 1 (Ethernet A-D) + Type 4 (Ethernet
  Segment) routes, ES-Import RT, and **DF election**.
- New ext-comms: EVI-RT EC (`0x06` / `0x0A`–`0x0D`) and ES-Import RT.
- Synch state machine + timers: last-member-query, Maximum Response Time;
  DF advertises/withdraws the SMET from the combined `(x,G)` state.

## Risks / call-outs

- **VID ↔ VNI mapping.** Snooped MDB entries are per-bridge-VID; resolve to
  VNI via the VXLAN device + bridge-vlan (reverse of `vni_ifindex_map`).
- **Fork dependency.** Phases 4a / 5a edit the external
  `netlink-packet-route` fork; the commit must be pushed and the Cargo rev
  bumped before CI is green (CI builds from the git rev, not the local
  working tree).
- **Naming overload.** `rib::Message::MdbAdd` / `mdb_add` are the Type-3
  *flood* path, not kernel MDB — rename in Phase 4b to avoid confusion
  with the real selective MDB added in Phase 5a.
- **RFC 7606.** Malformed Type-6 (bad src/grp length, illegal flags per
  family/version) ⇒ treat-as-withdraw, not session reset.
- **IPv6/MLD parity** is maintained across every phase, not bolted on.
