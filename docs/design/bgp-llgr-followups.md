# BGP well-known communities / LLGR — follow-ups

Snapshot of remaining work as of `main` ≈ commit `4558d246`
(PR #1311 merged). RFC 1997 egress suppression and the RFC 9494
receive-side rules are both shipped; this memo captures the deferred
slices so a future session can pick from a known list instead of
re-deriving the state of the world.

Companion docs:
- `bgp-well-known-communities.md` — the per-community status table
  (what is enforced, what is policy-level by design) and the
  enforcement design notes. Keep that table in sync when any item
  below ships.

Before picking the next item, follow the project's standing guidance:
recommend the smallest meaningful slice with the main tradeoff, let
the user redirect, and ship one branch / one PR at a time.

## What shipped (in order)

- **#1305** — Community/ExtCommunity/LargeCommunity storage moved to
  `BTreeSet` (dedup + canonical order); the precondition for cheap
  community checks on the hot path.
- **#1310** — RFC 1997 egress gate
  (`community_suppresses_advertisement` in `zebra-rs/src/bgp/route.rs`,
  hooked into `route_update_ipv4/ipv6/evpn`): NO_ADVERTISE → no peer,
  NO_EXPORT / NO_EXPORT_SUBCONFED → no eBGP peer. Runs BEFORE outbound
  policy; depends only on peer type (part of `UpdateGroupSig`), so it
  is safe under the per-group advertise memo. `@bgp_community` BDD
  gained the z4 eBGP edge to observe both behaviors.
- **#1311** — RFC 9494 receive side, three slices:
  1. Routes *received* with LLGR_STALE are depreferenced (ingest paths
     OR `attr_has_llgr_stale` into `BgpRib.stale`; `is_better` does
     the rest; the community is never stripped on re-advertisement).
  2. §4.3 capability gate `llgr_blocks_advertisement` — per-PEER
     state, so it sits OUTSIDE the group memo (split-horizon pattern)
     **plus** an `llgr_ok` member filter in `flush_ipv4`/`flush_ipv6`
     (the group cache fans out per-group; an advertise-time gate alone
     would leak via the flush). Observable via the `llgr_excluded`
     update-group counter.
  3. §4.2 NO_LLGR — the VPNv4/EVPN stale-marking blocks partition the
     Adj-RIB-In first: NO_LLGR routes are removed and withdrawn, only
     the rest are stale-marked.

## Remaining slices

### 1. EVPN stale eviction on timer expiry (smallest, correctness)

`stale_route_withdraw` (route.rs, `Event::StaleTimerExipires` handler)
only walks `peer.adj_in.v4vpn`. EVPN routes ARE stale-marked and
re-imported with a stale timer started for `(L2vpn, Evpn)`, but when
that timer fires nothing evicts them — retained EVPN routes outlive
the long-lived window. Mirror the v4vpn walk over `peer.adj_in.evpn`
(withdraw via `route_evpn_withdraw`, clear the entries). Pre-existing
gap; one function, unit-testable shape.

### 2. Stale retention coverage beyond VPNv4 + EVPN

The peer-down retention blocks cover only VPNv4 and EVPN; IPv4
unicast, IPv6 unicast, VPNv6, and labeled-unicast v4/v6 simply
withdraw everything on session loss even when LLGR was negotiated for
those AFI/SAFIs (the labeled-unicast gap is called out in a comment
near the stale blocks). Per AFI/SAFI this means: mark adj-in stale +
attach LLGR_STALE + re-import + start the per-AFI/SAFI stale timer +
extend `stale_route_withdraw` eviction. The #1311 egress gates and
ingest depreference already key off `rib.stale`/the community, so they
apply automatically as coverage grows. Suggest one PR per AFI/SAFI
family, v4-unicast first (most observable in BDD).

### 3. RFC 9494 §4.6 partial-deployment knob

"MAY be advertised to neighbors that have not advertised the
capability" provided the neighbor is internal, NO_EXPORT is attached,
and LOCAL_PREF is set to 0. Today the strict §4.3 SHOULD-NOT
(suppress) is unconditional. This is an opt-in per-neighbor (or
per-instance) YANG knob; the egress sites already centralize on
`llgr_blocks_advertisement`, so the knob mostly changes that
predicate's outcome into "rewrite attr instead of suppress" on the
iBGP paths. Mind the update-group signature trap: the rewrite varies
per-peer, so it must stay outside the memo like the gate itself.

### 4. LLGR BDD feature

None exists. Requirements worked out during #1311:
- Stale retention only covers VPNv4/EVPN, so the topology must be an
  L3VPN (reuse the `bgp_interas_option_b` PE/ASBR shape or a smaller
  2-PE + RR variant) with `long-lived-graceful-restart` enabled
  per-neighbor.
- Session drop: the harness has `I bring link down in namespace`
  (bdd/tests/cucumber.rs) — an ungraceful drop, which is exactly what
  LLGR needs (a clean stop sends withdraws).
- Timing: detection is hold-timer bound (default 90 s) — either wait
  ~100 s in the feature or add a hold-time knob to the configs to
  shorten the run.
- Assertions: route survives with 'S' status + LLGR_STALE community
  in `show bgp ipv4 <addr>` detail on the helper; NOT re-advertised to
  a non-LLGR third peer (the §4.3 gate); evicted after stale-time;
  NO_LLGR variant evicted immediately.
- Remember the BDD invariants: feature-unique namespace prefix, no
  tag-prefixing collisions, explicit Teardown scenario, and verify
  `/usr/bin/zebra-rs` md5 before AND after the run (parallel worktrees
  stomp it mid-session).

### 5. Other community knobs (from the audit table)

- **GRACEFUL_SHUTDOWN (RFC 8326)**: a `graceful-shutdown` knob —
  attach GSHUT + LOCAL_PREF 0 on egress when the operator is draining
  the box, and lower LOCAL_PREF on tagged ingress routes. Until then
  it is matchable in inbound policy.
- **BLACKHOLE (RFC 7999)**: optional knob to install a discard route
  for tagged prefixes; operator policy today.
- **ACCEPT_OWN / ACCEPT_OWN_NEXTHOP (RFC 7611)**: niche RR/VPN
  feature; unimplemented, no current demand.
- **NO_PEER (RFC 3765)**: intentionally not enforced (advisory;
  bilateral-peer vs transit is not auto-determinable; FRR does not
  enforce it either). No work planned — recorded so nobody "fixes" it.

### 6. Investigation: VRF→global VPNv4 export row lost after a flap

Observed once during #1310 verification (BDD_KEEP aftermath of
`bgp_interas_option_b`): after a post-run session flap, pe1's VRF
table still held the customer route but its global VPNv4 table stayed
EMPTY for minutes — the per-VRF→global Export row was not re-emitted
on session re-establishment — while the peer showed Established with
`PfxRcd/Snt 1/1` and an empty `received-routes`. Downstream copies
survived only because no withdraw was ever sent. Needs a controlled
reproduction under the normal harness lifecycle before filing a fix;
if real, the bug is in the `BgpGlobalMsg::Export` lifecycle (the VRF
side believes it already exported and never re-sends).
