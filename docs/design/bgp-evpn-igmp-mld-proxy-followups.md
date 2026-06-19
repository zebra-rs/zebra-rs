# BGP EVPN IGMP/MLD Proxy (RFC 9251) — deferred items / follow-ups

Snapshot as of `main` ≈ commit `4da2868a` (2026-06-20). The Type-6
**SMET** feature is shipped and live-validated for single-homed PEs
(PRs #1477–#1511; see `bgp-evpn-igmp-mld-proxy.md` for the recap). This
memo records what was deliberately left out, why, and how a future
session would pick each up — roughly highest-value first.

## 1. Per-VTEP `dst` selectivity (vnifilter VXLAN MDB)

**The biggest gap.** Today a received SMET *registers* the group in the
**bridge** MDB (`bridge mdb add dev <bridge> port <vxlan> grp G`), which
is selective among local bridge ports but **not** across the overlay:
the group is delivered out the VXLAN and head-end-replicated to every
remote VTEP on the Type-3 zero-MAC FDB list. True
`(x,G)`-to-only-the-asking-VTEP delivery needs the kernel **VXLAN MDB**.

Why deferred: it is not a localized SMET change. The kernel rejects
`MDBE_ATTR_DST` on a plain VXLAN with `EINVAL` (verified; `iproute2`
drops it too — see the `mdb_install` comment). The per-VTEP form needs a
**VNI-aware VXLAN**:

```
ip link add vxlan10 type vxlan external vnifilter local <ip> dstport 4789
bridge vni add vni 10 dev vxlan10
bridge mdb add dev vxlan10 grp G [src S] src_vni 10 permanent dst <VTEP>
```

`external vnifilter` is a different VXLAN model from the plain
fixed-VNI + `local` device zebra-rs creates today (`vxlan_add` in
`zebra-rs/src/fib/netlink/handle.rs`), and it interacts with the
already-merged **Type-2 MAC FDB** and **Type-3 BUM flood** paths (which
assume the plain model). So this is its own design + phased series, not
a patch.

Approach when picked up:
- Decide whether zebra-rs adopts `external vnifilter` VXLANs wholesale
  (affects Type-2/3) or only for VNIs with proxy enabled.
- Retarget `mdb_install` to `dev = vxlan` with `MDBE_ATTR_SRC_VNI` +
  `MDBE_ATTR_DST` (+ `MDBE_ATTR_DST_PORT`); `dst` is already plumbed
  through `rib::Message::SmetInstall { … dst }` → `smet_install` →
  `mdb_install` (currently only logged).
- Add a BDD that asserts `bridge mdb show dev vxlan10` carries the
  `dst` (the current `@bgp_evpn_smet` asserts the bridge-MDB group only,
  because the plain-VXLAN kernel drops the `dst`).

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

All-active multihoming only; large. Prerequisites absent today:
- **Ethernet-Segment** support: Type 1 (Ethernet A-D) + Type 4
  (Ethernet Segment) routes, **DF election**.
- New ext-comms: **EVI-RT EC** (`0x06` / sub-types `0x0A`–`0x0D`) and
  **ES-Import RT**.
- Synch state machine + timers (last-member-query, Maximum Response
  Time); the DF advertises/withdraws the SMET from the combined
  `(x,G)` state across the ES.
The Type 7/8 NLRI wire layouts are recorded in the main design doc.

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
