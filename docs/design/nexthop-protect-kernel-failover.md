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
| 2 — switchover op | #1377 | `Message::ProtectSwitch` + `GroupProtect.active` + atomic group re-send; revert-on-reassert |
| 3 — IS-IS hook | #1378 | `process_bfd_down` emits `ProtectSwitch` per failed nexthop addr before SPF; `@tilfa_bfd` BDD for the link-up failure class |
| 4 — OSPF hook | #1379 | `process_bfd_event` (generic v2+v3) emits `ProtectSwitch` via `OspfVersion::prefix_ip`; `@ospfv2_bfd_frr` + `@ospfv3_bfd_frr` BDD |
| 5 — ECMP leg eviction | #1380 | TI-LFA skips ECMP destinations (surviving legs are the protection), so the fast path evicts the BFD-dead leg from kernel ECMP groups; `@ecmp_bfd_evict` BDD |

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
is **not needed** for plain/MPLS primaries.

### Phase-1 BDD findings (2026-06-12) — two probe blind spots

The first probes validated netlink acceptance and **rendering**, not
end-to-end traffic through encap'd members. The phase-1 BDD run
closed that gap:

1. **[REFUTED 2026-06-12 — see correction below]** ~~seg6 `mode
   inline` members black-hole inside groups~~. The original claim
   rested on a single tcpdump that captured zero packets and was
   never reproduced. A later deep dive (kernel source walk +
   `skb:kfree_skb` drop-reason tracing on the live 6.8 kernel)
   showed group-wrapped inline members emit byte-identical SRH
   packets to direct references, and the atomic group-replace ONTO
   an inline member works under live traffic. The kernel makes this
   structural: the lwtstate lives on the member `fib6_nh`
   (`nh_info->fib6_nh.fib_nh_lws`) and `ip6_rt_init_dst`
   (net/ipv6/route.c) copies it from the SELECTED member identically
   for group and direct lookups — no group-conditional branch can
   lose it. The seg6 exclusions added on the back of the bad probe
   (phase-1 primary gate, phase-2 backup gate) are REMOVED; SRv6
   TI-LFA gets the same kernel fast path as MPLS. Post-mortem: the
   BDD failure that seeded the theory was finding 2 below (the
   rendering split), and the "confirming" 100%-loss pings were
   meaningless — a sandbox peer can't answer SRH-routed echoes, so
   loss is 100% even when forwarding works. Silent-drop claims
   require drop-reason tracing plus a reproduced capture.
2. **IPv6 group routes render with continuation lines.** `ip -6 route`
   prints `<prefix> nhid G proto X metric M` on line 1 and
   `nexthop ... dev D weight 1` on line 2 (IPv4 stays one line). Any
   text assertion expecting `dev D proto X metric M` as one substring
   breaks. Applies to every wrapped v6 primary — MPLS and (after the
   un-exclusion) SRv6 alike — sweep `bdd/` route asserts per the
   show-grammar rule; the combined asserts in the four SRv6 tilfa
   features were split when the exclusion was removed.

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

Kernel groups can't nest — `valid_group_nh`
(net/ipv4/nexthop.c:1228) rejects both hash-threshold and resilient
groups as members — so a `Multi` primary's ECMP group **is** the
switch point, with no extra indirection. What shipped in phase 5
(#1380) is **leg eviction**: `REPLACE Gmulti {leg1, leg2} → {leg2}`
on a BFD-dead leg, while leg link-down stays autonomous (the kernel
shrinks the group itself). The deeper design space is in
**§7. ECMP protection design space** — the nesting ban costs nothing
functionally, because flat membership editing expresses every
protection semantic.

Caveat (intended behavior since #1380): a `Multi` group is keyed by
member set and may be shared by unprotected routes with the same
ECMP set; editing its membership rewires those too. For eviction
that is the correct outcome — the leg is dead for everyone.

### Why an indirection group, not a value-overwrite of the primary

A natural-looking alternative to `Gp` is rewriting the primary
nexthop object in place (`RTM_NEWNEXTHOP` REPLACE of nhid 10 with the
backup's gateway/encap) — also one atomic message rewiring every
referencing route. Rejected because the protected thing is the
*(primary, backup) pair*, while a nexthop object's id is an
*identity shared by every consumer of that value*:

1. one primary can carry several per-destination repairs (TI-LFA is
   per-destination): pairs (10,11) and (10,12) need to switch to
   *different* targets — value-overwrite of nhid 10 can only pick
   one; pair-keyed `Gp`'s switch independently;
2. nhid 10 is shared by unprotected routes, other protocols'
   routes, and ECMP groups holding it as a leg (kernel members
   reference by id) — overwriting hijacks them all;
3. `NexthopMap` dedup keys are value-based (`(table, addr)`,
   `(addr, labels)`): after an overwrite the daemon's gid 10 means
   "10.0.0.2" while the kernel object forwards elsewhere — every
   resolve during the failure window installs routes onto a lying
   object;
4. auditability: post-overwrite, nhid 10 and nhid 11 have identical
   contents and no trace of which is switched;
   `ip nexthop show id <Gp>` showing the backup member IS the audit
   trail.

Same pattern as FRR's PIC path-list indirection: separate the
identity routes bind to from the value that changes at failover.

## 4. Data-model changes (phase 1–2)

- `NexthopProtect` gains `gid: usize` — the indirection-group id,
  mirroring `NexthopMulti.gid`. `gid == 0` means "no kernel
  indirection" (Multi primary, or `use_nhid` off).
- `NexthopMap` gains `Group::Protect(GroupProtect)`:
  `GroupCommon` + `primary_gid` + `backup_gid` +
  `active: Primary | Switched` (phase 2), keyed via
  `fetch_protect((primary_gid, backup_gid))`. Holds refcnts on both
  members so GC ordering is safe.
- Resolver (`rib_resolve_nexthop{,_v6}` Protect blocks): after
  resolving both members, allocate `Gp` when the primary is `Uni`.
- `FibHandle::nexthop_add`: `Group::Protect` arm installs a 1-member
  `NHA_GROUP` (same encoding as `Multi`, one entry) holding the
  ACTIVE member. Install order: members first, then `Gp`
  (`nexthop_sync` ordering); delete in reverse (`nexthop_unsync`).
  There is no separate `protect_switch` FIB method: the install
  request already carries `NLM_F_REPLACE`, so re-sending the group
  after an `active` flip IS the atomic switchover.
- Switchover flow (phase 2): `Message::ProtectSwitch { addr }`
  (table-scoped) → `route::protect_switch` walks
  `protect_switch_candidates` (active primary matches the failed
  adjacency, backup is a live non-seg6 Uni) → flips
  `active = Switched` → re-sends the group. Revert is driven by the
  producer: re-adding the same (primary, backup) pair —
  the post-flap SPF — resets `active` to `Primary` with a pending
  re-install, and the next sync re-sends the group with the primary
  member (same REPLACE mechanics). Validity in the sync passes
  follows the active member.
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
  irrelevant: local-SID installs aren't protected routes. (SRv6
  *encap'd* primaries and backups participate fully — the temporary
  exclusion is gone, see the corrected Phase-1 findings.)
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

## 7. ECMP protection design space (post-phase-5 notes, 2026-06-12)

The group-nesting ban looks like a limitation but isn't: the
indirection group's value is "a stable identity with atomically
editable membership", and an ECMP primary already IS one. Every
protection semantic is expressible by flat `NLM_F_REPLACE` edits on
the ECMP group itself:

| Failure | Flat edit on `Gmulti` | Semantics |
| --- | --- | --- |
| one leg dies, no per-leg repair | `{leg1,leg2} → {leg2}` | eviction — survivors carry (shipped, #1380) |
| one leg dies, leg has a repair | `{leg1,leg2} → {repair1,leg2}` | per-leg repair swap — a repair is a Uni, a legal member; inherit the dead leg's weight to preserve UCMP shares |
| all legs die (BFD-detected) | `{legs…} → {repair}` | whole-group failover; would close the blackhole window phase 5 leaves to SPF |
| all legs die (link-down) | none needed | kernel flushes members → empty group + routes deleted → `metric+1` shadow forwards |

Rows 2–3 have **no producer**: TI-LFA deliberately computes no repair
for SPF-level ECMP destinations (`ospf/tilfa.rs` skips
`nexthops.len() != 1`) because equal-cost survivors are loop-free
alternates by construction, so `Multi` primaries never carry a
Protect pair. The mechanism is ready if the IGPs ever stamp per-leg
repairs.

Known costs of flat editing, with fixes if ever needed:

- **shared-group blast radius** — `Gmulti` is deduped by member set,
  so edits also rewire unprotected routes sharing the set. Correct
  for eviction; debatable for a repair swap. Fix: stop deduplicating
  protected ECMP groups — a private group per protected set, keyed
  `(member_set, backup_set)` like `fetch_protect`.
- **flow reshuffle on edit** — hash-threshold groups recompute
  bounds, disturbing ~1/N of surviving flows. Fix: create protected
  ECMP groups as resilient (`NHA_RES_GROUP`); buckets stay pinned and
  only the dead member's buckets migrate.
- **no zero-weight standby** — member weight minimum is 1 (wire
  encoding `weight-1` in a u8), so a "parked" repair member would
  carry ~1/256 of steady-state flows. Not a viable protection shape.

Escalation ladder beyond flat editing (none needed so far):

1. **Binding-SID-style indirection** — route → single labeled Uni →
   ILM / local SID fans out to the ECMP; the route-level protected
   object becomes a wrappable Uni again. Natural in SR networks;
   costs a label layer per packet and a state layer per install.
2. **eBPF/XDP dataplane** — map-based `{legs, repairs, active}` with
   in-place atomic flips; the `offload/` infrastructure exists.
   Maximum freedom, maximum maintenance.
3. **Upstream kernel work** — native backup members in nexthop
   groups (FRR's zebra dataplane model and SAI both already model
   this; netlink simply never grew it). The better long-term fix
   than a depth-1 nesting allowance.
