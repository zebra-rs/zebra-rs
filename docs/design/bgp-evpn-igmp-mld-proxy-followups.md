# BGP EVPN IGMP/MLD Proxy (RFC 9251) — deferred items / follow-ups

Snapshot as of `main` ≈ commit `4da2868a` (2026-06-20). The Type-6
**SMET** feature is shipped and live-validated for single-homed PEs
(PRs #1477–#1511; see `bgp-evpn-igmp-mld-proxy.md` for the recap). This
memo records what was deliberately left out, why, and how a future
session would pick each up — roughly highest-value first.

## 1. Per-VTEP `dst` selectivity (vnifilter VXLAN MDB) — DONE (#1549, #1550)

**Was the biggest gap.** A received SMET registered the group only in
the **bridge** MDB (`bridge mdb add dev <bridge> port <vxlan> grp G`) —
selective among local bridge ports but **not** across the overlay, so
the group was head-end-replicated to every remote VTEP on the Type-3
BUM list.

**Done.** zebra-rs now adopts the **`external vnifilter`** VXLAN model
wholesale (Option A from the plan) and programs a received SMET as
**two** MDB entries: the bridge MDB (registers the VXLAN port so the
snooping bridge forwards the group into the overlay) plus a **VXLAN
MDB** on the VXLAN device itself carrying `MDBE_ATTR_DST` (the
originating VTEP) + `MDBE_ATTR_SRC_VNI` — so the kernel replicates the
group only to the PE that asked for it. Shipped across:

- **P1a** — seg6 fork `netlink-packet-route@b03a738`:
  `tunnel::TunnelMessage` (`RTM_NEWTUNNEL` = `bridge vni add`,
  `VXLAN_VNIFILTER_ENTRY`) + the MDB `dst`/`src_vni` readback decode.
- **P1b (#1549)** — `vxlan_add` → `external vnifilter` (`CollectMetadata`
  + `Vnifilter`, no fixed id); `bridge vni add` per VNI via
  `vni_filter_add`; Type-3 BUM `mdb_add`/`del` carry `src_vni`; `link.rs`
  sources the L2VPN VNI from config when the kernel reports id 0. Type-2
  needed no change (self FDB already had `src_vni`).
- **P4 (#1550)** — `mdb_install` adds the VXLAN MDB entry
  (`dev = vxlan`, `MDBE_ATTR_DST`/`SRC_VNI`, via a shared `mdb_send`);
  `dst`/`vni` were already plumbed through `SmetInstall`. `@bgp_evpn_smet`
  now asserts `bridge mdb show dev vxlan10` carries the `dst` for (*,G)
  and (S,G), plus withdrawal.

Validated on kernel 6.8 / iproute2 **7.0.0** (the plan doc's assumed
6.1.0 tooling blocker was moot — the host had been upgraded, so the
VXLAN MDB `dst` is directly BDD-observable). Full EVPN BDD suite
(7 features / 33 scenarios) green on the integrated state. Design doc:
`bgp-evpn-smet-pervtep-dst-plan.md`; book: `ch-02-32` / `ch-00-04`.

## 2. Don't originate SMET for link-local / well-known groups — DONE (#1516)

**Was**: a snooping bridge auto-joins IPv6 link-local solicited-node
groups (`ff02::1:ffXX:XXXX`, `ff02::2`, …); those `RTM_NEWMDB` entries
flowed all the way to `evpn_originate_smet`, so the speaker advertised
SMET for link-local control multicast.

**Fixed** by `smet_advertisable_group()` (`bgp::route`): both
`evpn_originate_smet` and `evpn_withdraw_smet` skip IPv4 `224.0.0.0/24`
(local network control block) and IPv6 interface-/link-local scopes
(scope nibble ≤ 2). Unit test + a non-vacuous `@bgp_evpn_smet` assert
(`show bgp evpn` excludes `ff02` while the `239.1.1.1` SMET is present).

## 3. SMET Flags fidelity (from kernel MDB group-mode)

`smet_flags()` (`zebra-rs/src/bgp/route.rs`) sets the RFC 9251 §9.1
Flags octet from the group family + source presence (IPv4 → IGMPv3,
IPv6 → MLDv2; exclude for `(*,G)`, include for `(S,G)`). The kernel MDB
entry actually exposes the **include/exclude mode** via
`MDBA_MDB_EATTR_GROUP_MODE`, so the IE bit could be real instead of
inferred. The IGMP/MLD **version** (v1/v2/v3) is *not* surfaced by the
kernel MDB, so the version bits stay an approximation either way.
Approach: decode `MDBA_MDB_EATTR_GROUP_MODE` in the fork's
`mdb/entry.rs`, carry it on `FibMdbEntry`/`RibRx::SnoopJoin`, use it in
`smet_flags()`. Touches the fork (another `seg6` push + the gitignored
Cargo.lock auto-tracks the tip).

## 4. Multicast Flags EC capability gate

RFC 9251's ingress-replication filtering replicates `(x,G)`
selectively only toward egress PEs that advertised **both** the
Multicast Flags EC (on their IMET) and a matching SMET. Today the
selective MDB install isn't gated on the originator's MF EC — it's
harmless (the kernel floods unregistered groups to non-proxy PEs
anyway), so this is an optimization, not correctness. Needs the
per-`(RD/VTEP)` capability table that was deferred from Phase 3: parse
+ store the MF EC from received IMET (`as_evpn_mcast_flags` already
exists), then consult it in `route_evpn_export_selected`'s Smet arm.

## 5. Per-VLAN VID mapping

`smet_install` programs MDB entries with **VLAN 0** (`vid: 0`,
non-VLAN-aware bridge). A VLAN-aware bridge needs the snooped/derived
VID threaded through: the snoop side already carries `FibMdbEntry.vid`;
the install side hardcodes 0 (`smet_install` in
`zebra-rs/src/rib/inst.rs`). Map VID↔VNI via the bridge-vlan / VXLAN
vlan-tunnel config and pass it to `mdb_install`.

## 6. Type 7 / Type 8 multihoming synch routes

**Codec + control-plane stub: DONE.** Type 7 (IGMP/MLD Join Synch) and
Type 8 (IGMP/MLD Leave Synch) are now first-class in the BGP-packet
codec and the EVPN RIB:

- **NLRI codec** (`crates/bgp-packet/src/attrs/nlri_evpn.rs`):
  `EvpnIgmpJoinSync` / `EvpnIgmpLeaveSync` structs, `EvpnRoute` +
  `EvpnPrefix` variants (route types 7/8, ESI in the key), parse/emit,
  `Display` (with an `esi_display` helper), round-trip unit tests. The
  Type-8 `Reserved(4)` + `MaximumResponseTime(1)` + `Flags(1)` tail is
  handled; the Flags / Max-Response-Time ride off the route key.
- **Ext-comms** (`ext_com.rs`): **ES-Import RT** (`0x06`/`0x02`,
  auto-derived from the ESI) and **EVI-RT EC** (`0x06`/`0x0A`–`0x0C`,
  via `evi_rt_from_rt`), with predicates, accessors, `Display`, tests.
  EVI-RT Type 3 (IPv6, `0x0D`, 20-octet EC) is still out — the
  `ExtCommunityValue` is fixed 8-octet and zebra RTs are 2-octet-AS.
- **RIB stub** (`bgp/route.rs`): received Type-7/8 routes are stored,
  best-path-selected, and **re-advertised / route-reflected** through
  the generic EVPN path; the per-path Flags / Max-Response-Time are
  stamped on the `BgpRib` (`smet_flags` / `igmp_max_resp_time`) so a
  reflected route stays faithful. `route_evpn_export_selected` treats
  them as **kernel no-ops**. Origination helpers
  `evpn_originate_igmp_join_sync` / `…_leave_sync` (+ withdraws) attach
  the ES-Import RT + EVI-RT EC; they are `#[allow(dead_code)]` until an
  ES-snoop trigger calls them (see below).
- **CLI**: `show bgp evpn igmp-join-sync` / `igmp-leave-sync` filters +
  legends + `exec.yang` enums.

**Still deferred (the actual multihoming data plane).** The
Ethernet-Segment foundation these all sit on now has its own design +
phasing plan: `bgp-evpn-ethernet-segment.md`. The remaining gaps:
- **Ethernet-Segment** support: Type 1 (Ethernet A-D) + Type 4
  (Ethernet Segment) routes, **DF election** — see the ES design doc.
- Synch state machine + timers (last-member-query, Maximum Response
  Time); the DF advertises/withdraws the SMET from the combined
  `(x,G)` state across the ES.
- The **organic origination trigger**: a snoop on a multihomed ES that
  calls the `evpn_originate_igmp_*_sync` helpers (today nothing does).
- **Kernel MDB synch** between the PEs on the ES.
- EVPN **import-RT filtering** so the ES-Import RT actually scopes
  distribution (today Type-7/8 reflect to all EVPN peers; the RTs are
  carried but not yet consulted on import). Note `route_rts_from_ecom`
  filters `low_type == 0x02` regardless of high-type and is VPNv4/v6
  only, so the ES-Import RT (`0x06/0x02`) causes no collision today.
- **Live validation** (BDD): **DONE** for reflection — the
  `clear bgp debug igmp-{join,leave}-sync-{originate,withdraw} <spec>`
  test command drives the origination helpers and `@bgp_evpn_igmp_sync`
  asserts z1 imports/renders the routes (prefix + ES-Import RT + EVI-RT).
  Real ES-multihoming validation still waits on the ES foundation.

## 7. Minor / cosmetic

- **Rename the misnamed Type-3 flood path.** `rib::Message::MdbAdd` /
  `fib::mdb_add` actually program a zero-MAC **FDB** ingress-replication
  row (BUM flood), not the kernel MDB. SMET uses the distinct
  `SnoopJoin`/`SmetInstall` + `mdb_install` path, so there's no
  functional overload — but the names mislead. Rename (e.g.
  `BumReplicationAdd`) when convenient.
- **`show bgp evpn` JSON.** `show_bgp_evpn` returns `[]` for JSON
  (intentional placeholder since the first EVPN slice); SMET shares
  that gap.
