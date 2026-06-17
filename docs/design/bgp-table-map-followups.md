# BGP table-map — recap & follow-ups

Snapshot as of `main` ≈ commit `cd72eadf` (2026-06-12). Table-map is
shipped for IPv4 + IPv6 unicast on the global instance: PR #1385 (v4
feature + `@bgp_table_map` BDD), #1393 (v6 + `@bgp_v6_table_map`
BDD), #1389/#1396 (book chapter
`book/src/ch-02-28-bgp-table-map.md`). This memo records the design
anchors a future session would otherwise re-derive, and the
deliberately deferred slices.

## What shipped

- **CLI/YANG**: bare `leaf table-map { type string; }` on every
  global afi-safi list entry (`zebra-rs/yang/zebra-bgp-table-map.yang`,
  imported by `config.yang`). Bare-leaf FRR spelling was an explicit
  user decision over a `container+presence` form. The Rust callback
  (`config_table_map`, `zebra-rs/src/bgp/config.rs`) gates commit to
  v4/v6 unicast (`table_map_afi_valid`).
- **Apply point**: `table_map_apply` in `zebra-rs/src/bgp/route.rs`,
  called from `fib_install_v4` / `fib_install_v6` — the single
  BGP→RIB install funnels. Permit rewrites a transient `Cow` clone
  (Loc-RIB and Adj-RIB-Out never see it); deny falls into the
  existing unconditional-withdraw branch. Binding storage is
  `LocalRib.table_map: BTreeMap<AfiSafi, BgpTableMap>` — the
  `sr_policy_local` placement trick, so config callbacks (`&mut Bgp`)
  and `BgpTop` both reach it; per-VRF tasks own a separate, empty
  `LocalRib` and are naturally inert.
- **Policy resolution**: `PolicyType::TableMap` watch on the shared
  `watch_policy` registry; `ident` encodes the family
  (`table_map_ident`/`_decode` in bgp/config.rs). `Register` replies
  **unconditionally** for this type (`policy_list: None` when the
  name doesn't resolve) so BGP resyncs exactly once on the definitive
  answer. **Unresolved name = deny-all** (FRR parity; user decision —
  note this is the *opposite* of peer `policy in/out` pass-through).
- **Refresh**: `Bgp::table_map_resync` (bgp/inst.rs) sweeps the
  family's Loc-RIB `Selected` map, install-only (best-path and
  egress attributes are unaffected, so nothing is re-advertised).
  Fired by the `PolicyRx` push (including the prefix-set→policy
  cascade) and by the delete callback.
- **Policy core generics** (from the v6 PR): `policy_list_apply_net`
  takes `IpNet` and is the real entry walk; `policy_list_apply`
  survives as the `Ipv4Nlri` wrapper so peer-policy call sites are
  untouched. **Any future v6 policy consumer should call `_net`** —
  this was the only blocker for v6 policy generally
  (`PrefixSet::matches` was already dual-stack).

## Deferred / remaining items

### 1. VRF afi-safi table-map

No config surface under `vrf <name> … afi-safi` yet; per-VRF
installs are unaffected by design (the VRF task's `LocalRib.table_map`
is always empty). To add it:

- YANG: augment the per-VRF afi-safi list (the `afi-safi-unicast`
  grouping in `zebra-afi-safi.yang`) the same way.
- The watch `ident` codec must grow a VRF dimension — today it is
  `0|1` for global v4/v6. Encode `(vrf_id, family)` or move to a
  registry.
- `PolicyRx` lands in the **global** event loop; per-VRF bindings
  need the update forwarded into the owning `BgpVrf` task
  (forward-to-full-instance pattern, like the IS-IS/OSPF VRF
  slices), and the resync sweep must run there against the VRF's
  own `LocalRib`.

### 2. IOS-style `filter` knob

IOS distinguishes `table-map <rm>` (attribute rewrite only; denied
routes still install unmodified) from `table-map <rm> filter`
(deny = don't install). We ship FRR semantics: always filtering.
Adding the IOS mode later collides with the bare-leaf choice — a
string leaf can't grow an optional trailing keyword in pure YANG
(see the `yang-cli-optional-arg-tradeoff` note): the options are a
breaking move to `container table-map { leaf policy; leaf filter
{ type empty; } }`, or an awkward sibling leaf
(`table-map-filter`). Decide only if someone actually asks for the
rewrite-without-filter mode.

### 3. IPv6 `set next-hop` rewrite

`SetNextHop::Address(IpAddr::V6(_))` is still a no-op in
`policy_list_apply_net` (route.rs) — the pre-existing "Phase H"
gap shared with peer policy, *not* table-map-specific. Wiring it:
set `BgpNexthop::Ipv6(addr)`, ideally guarded on the route's family
(an operator putting a v6 target in a v4-bound map should get a
no-op, not a corrupt nexthop). `SetNextHop::SelfAddr` also resolves
to the **v4 router-id** only; a v6 self needs a v6 local-address
source threaded into the apply signature. The book chapter's Scope
section documents the limitation — update it when this lands.

### 4. Operational visibility of the deny-all state

Nothing in `show` reveals whether a bound table-map's policy
resolved. Because unresolved = deny-all, a typo in the policy name
silently blackholes every install for the family until the operator
diffs the kernel against `show bgp`. A small show surface — e.g.
a line in `show bgp ipv4 summary` or a `show bgp table-map` — could
render `LocalRib.table_map`'s `name` vs `policy.is_some()`
("TMAP (resolved)" / "NOSUCH (unresolved — filtering all
installs)"). Cheap and high operator value; FRR offers nothing
comparable, so there's no parity constraint on the format.

### 5. Per-ECMP-leg application

FRR applies the route-map per nexthop leg inside its announce loop
(`bgp_zebra.c` ≈ 1381) and takes metric/tag overrides from the first
leg only. zebra-rs applies once to the single best path — correct
under the current `fib_install_*` contract ("at most one `BgpRib`
after best-path selection"). Revisit only if BGP multipath FIB
install lands; the apply helper already isolates the decision per
`BgpRib`, so the change would be confined to the install funnels.

### 6. Other address families

Labeled-unicast (`fib_install_labelv4/v6`), VPN, and EVPN install
paths have no table-map hook, and the commit gate rejects those
families. FRR's `bgp_fibupd_safi()` does cover labeled-unicast, so
LU is the one family with a parity argument for extension; the LU
install funnel is a separate function, so the hook would mirror the
unicast one. Deliberately out of scope until there's a concrete ask.

### 7. Testing constraint worth remembering

`delete …` spellings can't be pinned in the `manager.rs` `parse()`
harness — delete completion resolves against the running config tree
(the third `parse()` argument), not the schema, so every
delete-subtree path returns `Nomatch` with `None` config. Pin only
`set` spellings there; delete paths are covered by the BDD
`I apply command "delete …"` steps (both table-map features exercise
them).
