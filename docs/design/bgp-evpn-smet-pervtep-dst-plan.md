# EVPN SMET per-VTEP `dst` selectivity (VXLAN MDB) — design / scoping

Status: **proposed** (2026-06-19). Follow-up #1 from
`bgp-evpn-igmp-mld-proxy-followups.md`. Turns the shipped RFC 9251 SMET
control plane into a *truly* per-VTEP-selective data plane.

## Problem

The shipped Phase-5 dataplane (`fib::mdb_install`, PR #1506) installs a
received SMET as a **bridge** MDB entry:

```
bridge mdb add dev <bridge> port <vxlan> grp G [src S]
```

That registers the group on the VXLAN bridge port, so the snooping
bridge stops *flooding* it to local non-member ports — but it carries
**no per-entry destination**. When the group egresses the VXLAN it is
head-end-replicated to **every** remote VTEP on the Type-3 zero-MAC FDB
list. So across the overlay it is not selective: a `(*,G)` joined only
behind PE-B is still sent to PE-C, PE-D, … This was confirmed in
testing — the kernel **silently drops `MDBE_ATTR_DST` on a plain
VXLAN** (returns `EINVAL` if you force it), which is why Phase 5
deliberately omits the `dst` (the `dst` is plumbed end-to-end through
`rib::Message::SmetInstall { … dst }` → `smet_install` → `mdb_install`
but currently only logged).

Goal: deliver `(x,G)` only to the VTEPs whose SMET asked for it.

## Mechanism: the VXLAN MDB (kernel ≥ 6.3)

The kernel models per-VTEP multicast forwarding with a **VXLAN MDB** on
a **VNI-aware (`vnifilter`), externally-controlled** VXLAN device. The
MDB entry lives on the *VXLAN device itself* (not the bridge) and
carries the remote destination:

```
ip link add vtep type vxlan external vnifilter local <ip> dstport 4789
bridge vni add vni <N> dev vtep
# per (S,G) → remote VTEP:
bridge mdb add dev vtep port vtep src_vni <N> grp G [src S] permanent dst <VTEP-IP>
```

The netlink message is `RTM_NEWMDB` with `family=AF_BRIDGE`,
`ifindex=<vxlan>`, an `MDBA_SET_ENTRY` (`struct br_mdb_entry`), and —
**mandatory for a VXLAN device** — a NESTED `MDBA_SET_ENTRY_ATTRS`
carrying `MDBE_ATTR_SOURCE` (S), `MDBE_ATTR_DST` (remote VTEP), and
`MDBE_ATTR_SRC_VNI` (the VNI). (On a *plain* bridge MDB the
`SET_ENTRY_ATTRS` is optional and `MDBE_ATTR_DST` is rejected — the
opposite of the VXLAN MDB, which requires it.)

### Tooling note

zebra-rs emits netlink **directly**, so it is *not* limited by the host
`iproute2` (the test box ships 6.1.0, whose `bridge mdb` predates the
`dst`/`src_vni`/VXLAN-MDB options — that is why manual `bridge mdb add …
dst` probes fail with "Missing MDBA_SET_ENTRY_ATTRS"). The kernel
itself (6.8 here) supports it; we encode the attributes ourselves
(exactly as we already do for the Phase-5 `MDBE_ATTR_SOURCE` nest). The
`MDBE_ATTR_*` enum values come from `linux/if_bridge.h`
(`SOURCE=1`, `DST=5`, `DST_PORT=6`, `SRC_VNI=9`) — pin them against the
header during implementation.

## The architectural decision

`external vnifilter` is a **different VXLAN model** from the plain
fixed-VNI device zebra-rs creates today (`vxlan_add` in
`fib/netlink/handle.rs`: `InfoVxlan::Id(vni)` + `Local` +
`Learning(false)`). An `external` VXLAN delegates BUM/forwarding
decisions to the control plane rather than the device's own FDB. This
interacts with the **already-shipped** L2 EVPN paths:

- **Type-2 (MAC/IP)** — `mac_add`/`mac_del` program the bridge FDB with
  the remote VTEP as `dst`; under `external` the addressing/VNI
  plumbing differs (per-VNI `bridge fdb … src_vni`).
- **Type-3 (BUM)** — the misnamed `mdb_add`/`mdb_del` (a zero-MAC FDB
  *flood* row per remote VTEP) is the ingress-replication list; the
  `external vnifilter` model expresses BUM via the VXLAN MDB too
  (a `grp 0.0.0.0`/all-zeros catch-all per VTEP) rather than zero-MAC
  FDB.

So this is **not a localized SMET patch** — it changes the L2
dataplane model. Two scoping options:

| Option | What | Pros | Cons |
| ------ | ---- | ---- | ---- |
| **A. Wholesale** | Every EVPN VXLAN becomes `external vnifilter`; rework Type-2 FDB + Type-3 BUM onto the VNI-aware model | One consistent model; unlocks per-VTEP SMET cleanly; aligns with how FRR/modern kernels do EVPN multicast | Touches shipped, working Type-2/3 paths — regression surface; bigger BDD matrix |
| **B. Per-VNI opt-in** | Only VNIs with `igmp-mld-proxy` use `external vnifilter`; others stay plain | Smaller blast radius on existing deployments | Two VXLAN models in one daemon; Type-2/3 must work both ways; more conditional code |

**Recommendation:** Option A, as its own phased series with FRR/IOS-XR
interop validation — the per-VNI split (B) doubles the L2 matrix for
little durable benefit, since the `external vnifilter` model is where
EVPN multicast is going anyway. **This is the decision to confirm
before any code.**

## Implementation sketch (Option A)

1. **Fork (`netlink-packet-route` seg6):** ensure `InfoVxlan` exposes
   `CollectMetadata`/external + the `vnifilter` flag, and add the
   `MDBE_ATTR_DST`/`SRC_VNI` encoders if we want typed helpers (today
   Phase 5 hand-rolls the nested attrs via `MdbAttribute::Other` —
   that path extends fine without a fork change).
2. **VXLAN creation (`vxlan_add`):** create `external vnifilter`; drive
   `bridge vni add` per VNI (RTM_NEWTUNNEL / `VNI`-filter netlink) as
   VNIs are learned.
3. **Type-2 / Type-3 rework** onto the VNI-aware model (the bulk of the
   work and the regression risk).
4. **`mdb_install`:** retarget to `dev = <vxlan>`, add
   `MDBA_SET_ENTRY_ATTRS { MDBE_ATTR_SOURCE?, MDBE_ATTR_DST=orig,
   MDBE_ATTR_SRC_VNI=vni }`. `dst`/`vni` are already plumbed; drop the
   bridge-vs-vxlan ifindex distinction in `smet_install`.
5. **Show / introspection:** `show bgp evpn` is unaffected; a
   `show evpn mdb`-style command could surface the programmed
   per-VTEP state (the host `bridge mdb show` is too old to render it).

## Phasing

- **P0** — this doc + the Option A/B decision.
- **P1** — fork/`vxlan_add`: create `external vnifilter` VXLANs + VNI
  filter; keep behavior otherwise identical (Type-2/3 still work).
- **P2** — port Type-3 BUM to the VXLAN-MDB catch-all; verify the
  existing `@bgp_evpn_ar` / Type-3 BDDs stay green.
- **P3** — port Type-2 MAC to `src_vni` FDB; verify Type-2 BDDs.
- **P4** — retarget `mdb_install` to the VXLAN MDB with `dst`; extend
  `@bgp_evpn_smet` to assert per-VTEP delivery.

## Risks / open questions

- **Regression surface.** Type-2/3 are shipped and BDD-covered; the
  model change must keep them green. This is the main risk.
- **Test harness.** The box's `iproute2` 6.1.0 can't render the VXLAN
  MDB (`bridge mdb show` won't show `dst`/`src_vni`), so the P4 BDD
  needs either a newer `bridge` or a daemon-side `show` + netlink dump
  assertion. (zebra-rs *programming* it is unaffected — only the test
  *observation* is.)
- **Interop.** Validate the on-wire VXLAN encapsulation + MDB-driven
  replication against FRR / a second stack, not just self-consistency.
- **Exact `br_mdb_entry` + `MDBE_ATTR_*` layout** for the VXLAN-MDB
  SET — pin against `linux/if_bridge.h` and a real kernel ACK (can't
  strace the old iproute2 for a reference; read kernel source or upgrade
  the host tool).
- **`bridge vni add` netlink** — confirm the exact message
  (`RTM_NEWTUNNEL` + `VXLAN_VNIFILTER_*`) the fork must emit.

## Decision & validation findings (2026-06-19)

**Model: Option A (adopt `external vnifilter` wholesale) — confirmed.**

Bench validation in a throwaway netns on this host (kernel 6.8) settled
the open questions, with one tooling blocker:

- **VXLAN creation: no fork change needed.** The fork's `InfoVxlan`
  already exposes `CollectMetadata(bool)` (external) and
  `Vnifilter(bool)`. `ip link add … type vxlan external vnifilter`
  + `bridge vni add vni N dev <vtep>` succeed.
- **Type-2 / Type-3 on the model: validated.** On an `external
  vnifilter` VXLAN, `bridge fdb add <mac> dev <vtep> src_vni N dst
  <VTEP>` works for both a unicast MAC (Type-2) and the all-zero
  `00:00:00:00:00:00` BUM row (Type-3). So both shipped paths port to
  the VNI-aware model via `src_vni`-keyed FDB — the regression risk is
  real but the mechanism is sound.
- **Fork prerequisite confirmed: `bridge vni add` is `RTM_NEWTUNNEL`,
  which the fork/rtnetlink does NOT expose.** Adding the VNI-filter
  netlink (message type + `VXLAN_VNIFILTER_ENTRY_*` attrs) to the
  `seg6` fork is **P1's first task**.
- **BLOCKER on the core deliverable's validation.** The VXLAN MDB with
  `dst` (the whole point) cannot be exercised with this host's tooling:
  `iproute2` is pinned at **6.1.0** (its `bridge mdb` predates
  `dst`/`src_vni`/VXLAN-MDB; `apt` candidate is also 6.1.0) and
  `pyroute2` is not installed. zebra-rs *emitting* it via netlink is
  unaffected, but we cannot independently *drive or observe* a
  reference entry to confirm the wire format or the forwarding result.
  Before P4 lands we need one of: (a) a newer `bridge`/`iproute2` built
  on the test box, (b) a daemon-side `show evpn mdb` that reads back the
  install via `RTM_GETMDB` (needs the fork's `mdb/entry.rs` to also
  decode `MDBE_ATTR_DST`/`SRC_VNI`), or (c) interop against a second
  stack. **This is the gating item for validatable P4 work.**

### Revised first steps

1. **Fork P1a** — `RTM_NEWTUNNEL` / VNI-filter add+del in the `seg6`
   fork (+ `MDBE_ATTR_DST`/`SRC_VNI` decode in `mdb/entry.rs` so the
   daemon can read its own VXLAN MDB back for tests).
2. **zebra P1b** — `vxlan_add` creates `external vnifilter`; drive the
   VNI filter per learned VNI; keep Type-2/3 green (likely requires
   landing the Type-2/3 `src_vni` FDB rework in the same PR, since the
   plain-model FDB stops working under `external`).
3. P2–P4 as before; P4 gated on the validation tooling above.

## Status — IMPLEMENTED & BDD-validated (2026-06-21)

The series shipped. The "validation tooling" blocker above is **resolved**:
the test host was upgraded to **iproute2 7.0.0 / kernel 6.8**, whose
`bridge mdb show dev <vxlan>` renders the VXLAN MDB `dst`/`src_vni`, so P4
is directly observable in BDD (no daemon-side readback needed after all).

- **P1a (fork)** — `netlink-packet-route` seg6 `b03a738`: `tunnel::TunnelMessage`
  (`RTM_NEWTUNNEL` = `bridge vni add`, `VXLAN_VNIFILTER_ENTRY`), plus the
  earlier `d2c1d85` MDB `dst`/`src_vni` readback decode.
- **P1b (model switch)** — PR #1549: `vxlan_add` → `external vnifilter`
  (`CollectMetadata`+`Vnifilter`, no fixed `id`); `bridge vni add` per VNI via
  `vni_filter_add`; Type-3 BUM `mdb_add`/`del` carry `src_vni`; `link.rs`
  sources the L2VPN VNI from config when the kernel reports `id 0`. Type-2
  needed no change (self FDB already had `src_vni`).
- **P4 (per-VTEP dst)** — PR #1550 (stacked on #1549): `mdb_install` keeps the
  bridge MDB (local membership → overlay) AND adds a VXLAN MDB on `dev=vxlan`
  with nested `MDBE_ATTR_DST` (originator VTEP) + `MDBE_ATTR_SRC_VNI`
  (+ `MDBE_ATTR_SOURCE` for (S,G)), via a shared `mdb_send`. Replicates the
  group only to the asking VTEP instead of BUM-flooding.

**Design choice vs the sketch:** the original sketch said "retarget
`mdb_install` to `dev = vxlan`" (replace the bridge MDB). The implementation
keeps **both** installs — the bridge MDB registers the VXLAN port so the
snooping bridge forwards the group into the overlay, while the VXLAN MDB
selects the destination VTEP. This mirrors FRR and avoids dropping local
bridge→overlay forwarding.

Validation (kernel 6.8 / iproute2 7.0.0): `@bgp_evpn_smet` extended to assert
`bridge mdb "vxlan10" … contains <dst VTEP>` for (*,G) and (S,G) + withdrawal;
green alongside `@vxlan_bridge` and `@bgp_evpn_ar`. `cargo fmt` +
`clippy --workspace --all-targets -- -D warnings` clean.

Deferred (unchanged): SMET-flags fidelity from kernel group-mode, MF-EC
capability gate, per-VLAN VID mapping, Type 7/8 multihoming synch.
