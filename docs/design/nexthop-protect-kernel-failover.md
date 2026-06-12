# Kernel-Side Failover for `Nexthop::Protect` — Design & Phasing Plan

Tracks moving TI-LFA failover from daemon-mediated reconvergence to
kernel-side switchover, built on the `Nexthop::Protect` primary+backup
pair introduced in #1370 (and the v6 resolver fix in #1373). This is
the living plan + status: the failure-class analysis, the kernel
primitives (probe-validated on the target kernel), the architecture,
and the phase-by-phase slice so a contributor can resume without the
conversation history.

Read this first if you're touching `rib/nexthop/inst.rs`
(`NexthopProtect`), `rib/nexthop/group.rs` / `map.rs`
(`Group::Protect`, `fetch_protect`), `rib/route.rs`
(`rib_resolve_nexthop{,_v6}`), or the `fib/netlink/handle.rs` install
paths for protected routes.

## Status (updated 2026-06-12)

| Slice | PR | What lands |
| ----- | -- | ---------- |
| 0 — `Nexthop::Protect` RIB shape | #1370, #1373 | explicit primary/backup pair, producers + consumers, v6 resolver fix |
| 1 — indirection group | #1374 | `Group::Protect` + `NexthopProtect.gid`; protected v4/v6 routes reference a 1-member kernel group; behavior-neutral |
| 2 — switchover op | — | `FibHandle::protect_switch` + `Message::ProtectSwitch` + nmap state |
| 3 — IS-IS hook | — | BFD/adjacency-down emits `ProtectSwitch` before SPF; BDD for the link-up failure class |
| 4 — OSPF hook | — | v2 + v3, same shape |
| 5 — ECMP leg-level replace | — | per-leg repair on `Multi` primaries |

## 1. Problem

Two failure classes behave very differently today:

| Failure | Detection | Who restores traffic today | Cost |
| --- | --- | --- | --- |
| Local link down | kernel netdev event | **kernel** — deletes the dead nexthop object and every route referencing it; the pre-installed `metric+1` repair route takes over | ~instant, autonomous |
| Remote failure, link up (neighbor crash, unidirectional loss) | BFD | **daemon** — BFD down → adjacency down → full SPF → per-prefix `RTM_NEWROUTE`/`DELROUTE` | O(prefixes) netlink ops, after SPF |

The second row is the gap: for BFD-detected failures the pre-installed
repair route is never used, because the primary route (lower metric) is
still in the FIB pointing at a dead gateway the kernel knows nothing
about. The pre-installed TI-LFA state buys nothing in exactly the case
TI-LFA exists for.

**Goal:** traffic restored in O(failed adjacencies) — one netlink
message each — independent of prefix count (PIC-style), with SPF
reconvergence happening afterwards at its own pace.

## 2. Kernel primitives

Upstream Linux (incl. 6.8) has **no native backup-member semantics in
nexthop groups** — group types are `mpath` and `resilient` only. FRR's
"backup nexthops" exist only in dataplanes that support them
(SAI/DPDK), not in the kernel netlink API. The design therefore
composes two primitives the kernel does have:

1. **Atomic group-membership replace** — `RTM_NEWNEXTHOP` +
   `NLM_F_REPLACE` on a group id swaps membership (RCU); every route
   referencing the id forwards via the new members immediately, with
   no route churn.
2. **Autonomous flush on link down** — the kernel deletes nexthop
   objects on a downed device, removes them from groups, deletes a
   group when its last member dies, and deletes routes referencing the
   deleted group.

### Probe results (6.8.0-124-generic, 2026-06-12)

All load-bearing assumptions validated in throwaway netns
(veth pairs, `ip nexthop` + live ping with per-device RX counters):

| # | Probe | Result |
| - | ----- | ------ |
| 1 | single-member `NHA_GROUP` | pass — `ip nexthop add id 100 group 1` accepted |
| 2 | encap'd nexthop as group member | pass — MPLS (`16002/16005`) and seg6 (H.Encap) members both accepted |
| 3 | atomic replace under live traffic | pass — RX counters flipped 6/0 → 0/6 across one `ip nexthop replace`; route object untouched (`nhid 100`); replace **onto the MPLS-encap member** (the real switchover op) accepted, route dump shows inherited label stack |
| 4 | link-down autonomy | pass — device down flushed the member, deleted the empty group **and** the primary route; the `metric+1` shadow route survived and forwarded (fib lookup + ping) with no userspace action |
| 5 | v6 route via group + replace onto seg6 member | pass — same semantics for IPv6 routes |

Probe 2 passing means the fallback design ("Plan B": `RTM_DELNEXTHOP`
the primary and let the kernel flush primary routes onto the shadows)
is **not needed**.

## 3. Design

### Steady state

```
route 10.0.0.0/24 metric m    --Nhid--> Gp (mpath group) --> { U_primary }
route 10.0.0.0/24 metric m+1  --Nhid--> U_repair
```

- `Gp` is a 1-member indirection group per protected primary,
  allocated in `NexthopMap` like any gid and keyed by
  `(primary_gid, backup_gid)` — two prefixes sharing a primary but
  carrying different repairs get distinct groups, so each switches to
  *its own* repair.
- `U_primary` / `U_repair` are the existing `Group::Uni` objects. The
  repair's MPLS stack / SRv6 segs already ride on the nexthop object
  (`fib/netlink/handle.rs` `nexthop_add`), so a membership swap
  carries the full repair encap (probe 3).
- The `metric+1` shadow route **stays**: it is the autonomous
  link-down path (probe 4) and covers the daemon-crash window.

### BFD-down fast path

```
BFD down on adjacency A
  → IGP sends Message::ProtectSwitch{ table_id, primary key } (before SPF)
  → RIB looks up affected Gp's in NexthopMap
  → one RTM_NEWNEXTHOP REPLACE id=Gp group={U_repair} per Gp
  → every protected prefix via A forwards over its repair
  → SPF runs; post-convergence routes replace everything as usual
```

Failover becomes detection-bounded (BFD interval ×3) plus
microseconds, instead of detection + SPF + per-prefix FIB churn.

### Recovery

No in-place revert. The switchover is a bridge; normal SPF
reconvergence supersedes it — `diff_apply` installs fresh routes and
the old `Gp`s drain via the existing refcnt GC. (`backup-as-primary`
already covers the "stay on repair" operator intent; flap damping can
come later if ever needed.)

### ECMP primaries

Kernel groups can't nest, so a `Multi` primary's ECMP group **is** the
switch point — no extra indirection:

- leg-level BFD down: `REPLACE Gmulti {leg1, leg2} → {repair1, leg2}`
  (per-primary repair, correct TI-LFA semantics);
- leg link down stays autonomous (kernel shrinks the group).

Caveat for phase 5: a `Multi` group is keyed by member set and may be
shared by unprotected routes with the same ECMP set; replacing its
members rewires those too. Semantically acceptable (they lose a dead
leg) but must be called out in the phase-5 PR.

## 4. Data-model changes (phase 1–2)

- `NexthopProtect` gains `gid: usize` — the indirection-group id,
  mirroring `NexthopMulti.gid`. `gid == 0` means "no kernel
  indirection" (Multi primary, or `use_nhid` off).
- `NexthopMap` gains `Group::Protect(GroupProtect)`:
  `GroupCommon` + `primary_gid` + `backup_gid`, keyed via
  `fetch_protect((primary_gid, backup_gid))`. Holds refcnts on both
  members so GC ordering is safe. Phase 2 adds the
  `active: Primary | Switched` state.
- Resolver (`rib_resolve_nexthop{,_v6}` Protect blocks): after
  resolving both members, allocate `Gp` when the primary is `Uni`.
- `FibHandle::nexthop_add`: `Group::Protect` arm installs a 1-member
  `NHA_GROUP` (same encoding as `Multi`, one entry). Install order:
  members first, then `Gp` (`nexthop_sync` ordering); delete in
  reverse (`nexthop_unsync`).
- `route_ipv{4,6}_add/del` Protect arm: the primary route's `Nhid`
  becomes `pro.gid` (when non-zero) instead of the member gid; the
  shadow route is unchanged. With `use_nhid` off, everything stays
  exactly as today (gateways embedded per route) — the feature is
  inherently gated on nexthop-object support (kernel ≥ 5.3).
- Self-heal: probe 4 shows the kernel deletes `Gp` behind our back on
  link down — `Group::Protect` must join the existing
  `nexthop_force_reinstall` / re-resolve machinery from the start
  (same "kernel silently dropped the object" pattern as `Uni`/`Multi`).

## 5. Constraints

- **seg6local** can't ride nexthop objects (existing constraint) —
  irrelevant: local-SID installs aren't protected routes. SRv6 H.Encap
  repairs work (probe 2/5).
- `show nexthop` should render `Group::Protect` (+ active member from
  phase 2). Route show output is unchanged; RIB/kernel divergence
  during a switchover is bounded by SPF reconvergence.
- Legacy kernels (`use_nhid == false`): no indirection, no fast path;
  behavior identical to pre-phase-1.

## 6. Test plan

- Unit: `fetch_protect` allocation/dedup/refcnt; resolver stamps
  `pro.gid` (v4 + v6 — see #1373 for why both paths need pinning);
  install-order in `nexthop_sync`.
- BDD (phase 1): existing `@isis_tilfa`, `@isis_tilfa_srv6*`,
  `@ospfv2_tilfa`, `@ospfv3_tilfa` must stay green — phase 1 is
  behavior-neutral apart from the indirection level.
- BDD (phase 3+): new scenario for the link-up failure class —
  ip6tables-style drop (the BFD hold-down pattern from the IS-IS BFD
  series) asserting forwarding is restored via the repair label stack
  *before* IGP reconvergence rewrites the FIB.
