# BGP Per-AFI/SAFI Peer Membership Lists — Analysis

Status: **Direction confirmed — Option B** (§7), 2026-06-12.
Implementation follows the §8 sequencing: BDD scenario + bug-fix PRs
(B1, B2, B3) first, then the membership-index refactor.
Owner: Kunihiro Ishiguro
Last updated: 2026-06-12
Branch: `bgp-peer-list`

## 1. Problem statement

Every BGP RIB update/withdraw fan-out today iterates *all* peers and
re-checks, per route event: (a) is the peer Established, (b) did we
negotiate this AFI/SAFI with it, (c) is it an AddPath-send neighbor.
All three answers are already known — they are fixed when the session
reaches Established and cannot change until it leaves Established.

Proposal under evaluation: a per-AFI/SAFI (and AddPath-partitioned)
membership list containing only Established peers, so each fan-out
iterates exactly the interested peers.

## 2. Current state

### 2.1 The canonical scan idiom

Fourteen fan-out sites in `route.rs` share one shape:

```rust
let peer_addrs: Vec<IpAddr> = peers
    .iter()
    .filter(|(_, p)| p.state.is_established())
    .filter(|(_, p)| p.is_afi_safi(afi, safi))
    .filter(|(_, p)| !p.opt.is_add_path_send(afi, safi))   // or the complement, or absent
    .map(|(addr, _)| *addr)
    .collect();
for peer_addr in peer_addrs {
    let peer = peers.get_mut(&peer_addr).expect("peer exists");
    ...
}
```

The collect-then-relookup exists for the borrow checker (`&mut Peer`
plus `&mut BgpTop` cannot coexist with the iterator). Cost per route
event, per family: a full scan of every peer regardless of family, one
`Vec<IpAddr>` allocation, and one `BTreeMap` re-lookup per interested
peer. See §9 for the full site inventory.

### 2.2 The membership criteria are session-constant

- `is_afi_safi()` reads negotiated `cap_map` (send && recv,
  `peer.rs:1114`), populated during OPEN processing
  (`cap_register_recv`, `peer.rs:1727`). Config `afi-safi` changes do
  not touch `cap_map` until the next OPEN.
- AddPath direction is negotiated at OPEN (`cap_addpath_recv`,
  `cap.rs:89`) into `peer.opt.add_path`; RFC 7911 has no
  mid-session renegotiation.
- Established membership changes only at the FSM transition.

So all three list keys are immutable for the lifetime of an
Established session. The only maintenance events a derived list needs
are *enter Established* and *leave Established* — and both already
funnel through a single chokepoint (`peer.rs:1440-1480`: `route_sync`
then `update_group::attach`; `route_clean` then `detach`).

### 2.3 Three coexisting regimes

1. **Scan-and-filter** — the iteration source for every family (§2.1).
2. **Update groups** (`update_group.rs`) — already a per-AFI/SAFI
   membership list of Established peers (`UpdateGroup.members:
   BTreeSet<usize>`), with `addpath_send` in the signature, maintained
   at the FSM chokepoint. But it only tracks `TRACKED_AFI_SAFIS` =
   {IPv4-unicast, VPNv4, EVPN} (`update_group.rs:48`), and it is the
   *send mechanism* only for IPv4-unicast; iteration still starts from
   the scan everywhere.
3. **Per-peer caches** — VPNv4/VPNv6/EVPN batch into `peer.cache_*`;
   the remaining families direct-send.

The codebase therefore pays the scan cost everywhere *and* carries the
derived-membership staleness risk — and the two disagree about who
gets routes. The bugs below all live on that seam.

## 3. Latent bugs found during this analysis

All are invisible to the BDD suite because every feature applies
config *before* sessions establish, exercising only the initial
`route_sync` dump. No scenario anywhere adds a route after
Established. (See §8 step 0.)

### B1. IPv6-unicast incremental advertisement is dead — all peers

`route_advertise_to_peers_v6` (`route.rs:6800`) emits reach *only* via
`update_group::send_ipv6`, gated on
`peer.update_group_id.get(&(Ip6,Unicast))`. `attach()` enrolls only
`TRACKED_AFI_SAFIS`, which has no v6 entry, and nothing else writes
`update_group_id` — so the gate is always `None` and the reach is
silently dropped. The v4 twin has a no-group fallback
(`compute_advertise_outcome`) plus a `warn!` (`route.rs:2628`); the v6
path has neither. Withdraws direct-send and the initial
`route_sync_ipv6` dump works, which is why `bgp_ipv6_over_v4_session`
passes. Consequence: a v6 route received or a `network` statement
added after a session establishes is never advertised until session
reset. Introduced with the v6 advertise pipeline (`7b307f65`), which
added the group cache/flush but never extended `TRACKED_AFI_SAFIS`.

### B2. Unnumbered (interface-keyed) peers get no incremental updates in any family

Every fan-out scan uses `PeerMap::iter()`, which deliberately skips
`PeerKey::Interface` (`peer_map.rs:76-81`), and the
`Vec<IpAddr>` → `get_mut(&addr)` idiom structurally cannot name such a
peer — its remote link-local is never written into the address map
(`peer.rs:2495` doc comment). `route.rs` contains zero references to
`iter_all`/`PeerKey::Interface`. Interface-keyed peers receive the
ident-based initial `route_sync` and then nothing: no reach, no
withdraws, any family. (Group flush ships by ident and *would* reach
them, but nothing ever buckets on their behalf — group signatures
include the per-session `local_addr`, so unnumbered peers sit in
singleton groups whose caches are never filled.) This is the fourth
bite of the `iter()` vs `iter_all()` trap; the previous three were
show/sweep sites.

### B3. AddPath is half-implemented for VPNv6, EVPN, and Labeled-Unicast (wire-level bug)

The codebase has one *coherent* AddPath design, used by IPv4-unicast
and VPNv4: AddPath-send peers are excluded from the main advertise
path (`!is_add_path_send`) and served by dedicated twins —
`route_advertise_to_addpath` / `route_withdraw_from_addpath`
(`route.rs:2335,2412`) — which advertise **every selected candidate**
under its `local_id` and withdraw with `removed.local_id`.

Two other shapes exist:

- **IPv6-unicast**: AddPath peers are excluded from the only
  incremental function (`!is_add_path_send`, `route.rs:6814`) and no
  twin exists → AddPath-send v6 peers get nothing incrementally
  (subsumed by B1 today, but independent of it).
- **VPNv6 / EVPN / LU-v4 / LU-v6**: **no AddPath partition at all**
  (`route_advertise_to_peers_vpnv6` `route.rs:6885`,
  `route_advertise_evpn_to_peers` `route.rs:2874`,
  `route_advertise_to_peers_labelv4/v6` `route.rs:7112,7168`).
  AddPath-send peers fall into the best-path-only function, which
  consults `is_add_path_send` *inline* and stamps the reach NLRI with
  `id = rib.local_id`. That produces:

  1. **Malformed withdraws.** The withdraw side hardcodes `id = 0`
     (e.g. `route_withdraw_vpnv6(peer, rd, prefix, 0)`), and the wire
     emitters only write the 4-octet path-id when `id != 0`
     (`nlri_vpnv6.rs:152,238,280`; `local_id` allocation starts at 1,
     `route.rs:1005`, so 0 is the "no path-id" sentinel). On a session
     where AddPath was negotiated for the family, RFC 7911 §3 requires
     the path identifier on *every* NLRI — an id-less MP_UNREACH is
     malformed; a conformant receiver misparses the NLRI bytes and per
     RFC 7606 treats-as-withdraw the family or resets the session.
  2. **No-op withdraws / stale paths.** Even a tolerant receiver sees
     `(prefix, 0)`, which does not match the advertised
     `(prefix, local_id)` — the withdraw removes nothing.
  3. **Stale-path accumulation on replacement.** A best-path change
     advertises the new winner under a different `local_id`; for an
     AddPath peer that is an *additional* path, and the old one is
     never withdrawn.
  4. **Pending-cache leak.** `cache_remove_vpnv6(rd, prefix, 0)` keys
     the removal on `Ipv6Nlri{id:0}`, which fails Hash/Eq against the
     cached `{id:local_id}` entry — a queued reach survives its own
     withdraw and still goes out at flush.
  5. Best-only advertisement (no per-candidate fan-out) — legal per
     RFC 7911, but the capability is pointless without it.

  Reachability: real. The `add-path` leaf sits in the per-afi-safi
  list with **no `when` restriction**
  (`ietf-bgp-neighbor@2023-07-05.yang:182` — contrast
  `encapsulation-type` right below it), and `config_add_path` /
  `cap_addpath_recv` are family-generic. `afi-safi vpnv6 add-path
  send` plus a peer advertising receive ⇒ negotiated ⇒ the broken
  path fires. Latent until someone configures it.

### B4. Housekeeping gaps that the proposal would inherit or fix

- **Remove-without-detach (ABA hazard).** Three `peers.remove` sites
  (`config.rs:158`, `interface_neighbor.rs:289`, `inst.rs:1487`) never
  call `update_group::detach`; only the FSM transition does. Today a
  dangling ident in `group.members` is tolerated (`get_by_idx → None`),
  but `PeerMap` tombstones slots and *reuses the idx on same-key
  re-insert* (`peer_map.rs:52-62`) — delete an Established neighbor,
  re-add it, and a stale members entry points at the new, possibly
  Idle, differently-configured peer. If membership becomes the
  iteration source, this graduates from cosmetic to
  wrong-bytes-to-wrong-peer.
- **`PeerMap::iter_mut()` is accidentally quadratic** (per-slot linear
  `map.find`, `peer_map.rs:83-97`); used at `inst.rs:867,1229`.
- **BDD coverage gap**: no post-establish incremental-advertise
  scenario exists in any feature; that single scenario shape would
  have caught B1, B2, and B3.

## 4. Pros of the membership-list design

1. **Correctness by construction (the decisive one).** "Who receives
   this family" currently has two sources of truth — scan predicates
   and group membership — and they disagree (B1 *is* that
   disagreement; the defensive `warn!` at `route.rs:2628` exists
   because they can). One index consumed by every fan-out makes
   disagreement unrepresentable, and an ident-based index fixes B2 by
   construction (idents are key-agnostic).
2. **Tiny maintenance surface.** The list key is session-constant
   (§2.2): maintenance is exactly the existing attach/detach
   chokepoint plus detach-on-remove. This is not cache-invalidation
   whack-a-mole.
3. **Performance — real but second-order, except one case.** Per
   event, the O(total-peers) scan, the `Vec<IpAddr>` allocation, and
   the per-peer O(log n) re-lookup disappear. Honest sizing: below
   ~50 peers it is noise (policy/clone/intern/encode dominate); at
   hundreds of dynamic peers × full-table convergence (~10⁶ events)
   it is seconds of CPU and 10⁶ allocations. The clear win is the
   **sparse-family case**: today a flowspec/SR-Policy/RTC event scans
   every peer to find the two that negotiated the family, and a
   family with *zero* peers still pays a full scan per event; an
   index makes the empty case a free early-out.
4. **Kills the complementary-filter trap.** The AddPath split lives as
   mirrored `is_add_path_send` / `!is_add_path_send` predicates across
   twin functions that must stay complementary by hand; a missed
   complement is a double-send or a no-send. B3 shows four families
   where the partition is simply absent. A partitioned index
   (`{addpath_tx, plain}` per family) makes the split exhaustive by
   construction — every family must say what it does with the AddPath
   set, even if the answer is "nothing yet".
5. **Single registration point for new SAFIs.** The "new SAFI forgot a
   block" class has bitten before (peer-down `route_clean` leaked five
   AFI/SAFIs, fixed in #1329; `route_clean` is an 11-family hand-written
   enumeration, `route.rs:5731-6301`). Peer-down logic can enumerate
   the peer's actual memberships instead of a hand-maintained list.
6. **Observability.** Per-family peer counts become O(1);
   `show bgp update-group` gains a truthful substrate.

## 5. Cons and risks

1. **Derived state rots — demonstrated in this codebase.** B1 *is*
   membership rot in the existing half-implementation. A missed enroll
   fails silent-negative (peer receives nothing); a scan recomputes
   truth every time and is only wrong if the predicate is wrong.
   Mitigations are cheap but must actually be built: a `debug_assert`
   cross-check recomputing the scan filter against the index (debug/
   test builds), a `show` command exposing membership, and the
   v4-style fallback-plus-`warn!` posture in consumers during
   migration.
2. **Peer removal gets sharper.** B4's remove-without-detach ABA must
   be fixed as a precondition (detach-on-remove at all three sites, or
   generation-stamped idents).
3. **Most per-peer work remains.** Residual predicates are per-route ×
   per-peer and cannot be membership criteria: split-horizon (source
   ident), LLGR stale gating (route's stale bit × peer cap), RTC match
   (peer's `rtcv4/6` mutate mid-session via UPDATEs), iBGP→iBGP /
   RR-client suppression, NO_ADVERTISE/NO_EXPORT, SRv6-strict,
   outbound policy. Only the three list-key checks and the scan
   disappear.
4. **Migration is 14 sites of judgment, not one mechanical sweep.**
   Residual filters differ per site (SR-Policy excludes the source
   before the Established check; VPNv6/EVPN/LU have no AddPath
   partition — see B3; withdraw paths want the AddPath union). A
   *faithful* conversion changes behavior — it un-breaks B1/B2 — and
   those must land as explicit, BDD-pinned fixes, not silent side
   effects. Unit tests constructing `Peer`s directly need enrollment
   in setup (broad, shallow diff).
5. **Order and scoping details.** Ident order (creation order)
   replaces addr-sorted order — semantically fine for BGP, but tests
   pinning inter-peer output order may flake. Per-VRF BGP instances
   own their `PeerMap`, so the index is per-instance. Memory cost is
   negligible.
6. **Third-regime risk.** If the index lands beside update groups
   without unifying the chokepoint, the result is scan + groups +
   lists and the next family author picks one at random. Group attach
   must become a *consumer* of the same enroll/withdraw event.

## 6. What can and cannot be a membership criterion

In: Established, negotiated AFI/SAFI, AddPath-send direction — all
session-constant.

Out (stay in the loop or in the group signature): split-horizon, LLGR
stale gate, RTC match, iBGP/RR suppression, well-known-community
suppression, SRv6-strict, outbound policy, per-peer label/next-hop
choices. Policy identity stays in `UpdateGroupSig`, which remains the
byte-sharing layer above membership.

## 7. Design options

**A — Extend update groups to all families; iterate `group.members`.**
Tempting (structure exists, `addpath_send` already in the signature),
but the signature is policy identity, and `local_addr` is the
per-session socket address — eBGP groups degenerate to singletons. It
forces signature computation and group lifecycle onto event-driven
families that will never share canonical bytes (VPNv6, LU, flowspec,
SR-Policy, RTC), and "iterate a family" becomes "iterate all its
groups".

**B — First-class membership index; groups layered on top
(recommended).** Per-instance structure, e.g.
`BTreeMap<AfiSafi, FamilyMembers>` with
`FamilyMembers { addpath_tx: BTreeSet<usize>, plain: BTreeSet<usize> }`,
maintained by one `enroll(peer)` / `withdraw(peer)` pair at the
existing FSM chokepoint (which also drives group attach/detach), plus
detach-on-remove at the three removal sites. All fan-outs iterate
idents (`get_mut_by_idx`) — fixing B2 structurally; enrolling
v6-unicast (or keeping a v4-style fallback) fixes B1. Update groups
remain the IPv4-unicast byte-sharing optimization, fed from the same
event.

**C — Keep scans; fix the bugs only.** Add the v6 no-group fallback;
convert scans to ident-based collection over `iter_all()`. Cheapest,
preserves recompute-from-truth semantics, leaves the two-regime seam.
Note C's unnumbered fix (collect idents, not addrs) is already half
of B.

## 8. Recommended sequencing

0. **BDD: post-establish incremental advertisement scenario** —
   establish first, then add a route (network statement or
   redistribute), assert arrival. Numbered and unnumbered variants.
   This is the missing scenario shape that would have caught B1, B2,
   and B3; land it with (or before) the first fix so the fixes are
   pinned.
1. **Bug-fix PR (B1):** v6-unicast incremental — track v6 in
   `attach`, or add the v4-style fallback + `warn!`.
2. **Bug-fix PR (B2):** ident-based collection in the fan-out sites so
   interface-keyed peers are reachable.
3. **Bug-fix PR (B3):** decide per family: either implement the
   per-candidate AddPath twins for VPNv6/EVPN/LU, or guard the scans
   with `!is_add_path_send` + `warn!` (wire-safe, capability inert)
   until the twins exist. The malformed-withdraw hazard argues for
   doing at least the guard immediately.
4. **Refactor (Option B):** now a pure no-behavior-change
   consolidation — convert site by site with the `debug_assert`
   cross-check active; include detach-on-remove.

Steps 1–3 are independent small PRs per the
smallest-possible-PR-first rule; step 4 should not start until the
direction is confirmed on review of this document.

## 9. Appendix — fan-out scan inventory (`route.rs`)

| Line | Function | Family | AddPath handling |
|------|----------|--------|------------------|
| 2335 | `route_advertise_to_addpath` | v4-unicast / VPNv4 | addpath-only twin (per-candidate, correct ids) |
| 2412 | `route_withdraw_from_addpath` | v4-unicast / VPNv4 | addpath-only twin (withdraws `removed.local_id`) |
| 2515 | `route_advertise_to_peers` | v4-unicast / VPNv4 | excludes addpath; group memo + fallback + `warn!` |
| 2785 | `route_withdraw_evpn_to_peers` | EVPN | **no partition** (B3) |
| 2874 | `route_advertise_evpn_to_peers` | EVPN | **no partition**, inline id (B3) |
| 4678 | `srpolicy_reflect` | SR Policy | n/a (no addpath) |
| 4731 | `srpolicy_reflect_withdraw` | SR Policy | n/a |
| 4974 | `srpolicy_peer_addrs` | SR Policy | n/a (sync helper) |
| 5258 | `route_advertise_flowspec_to_peers` | Flowspec v4/v6 | n/a |
| 5290 | `route_withdraw_flowspec_to_peers` | Flowspec v4/v6 | n/a |
| 6800 | `route_advertise_to_peers_v6` | v6-unicast | excludes addpath; **group-gated, gate always None (B1)**; no twin |
| 6885 | `route_advertise_to_peers_vpnv6` | VPNv6 | **no partition**, inline id, withdraw id=0 (B3) |
| 7112 | `route_advertise_to_peers_labelv4` | LU-v4 | **no partition**, inline id (B3) |
| 7168 | `route_advertise_to_peers_labelv6` | LU-v6 | **no partition**, inline id (B3) |

Single-peer guards (not fan-outs): `route_soft_out_peer`
(`route.rs:2953`), `route_soft_in_peer` (`route.rs:3225`).

All fourteen fan-outs use `peers.iter()` (addr-keyed only — B2) and
none can reach an interface-keyed peer.
