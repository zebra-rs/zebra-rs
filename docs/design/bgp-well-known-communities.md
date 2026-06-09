# BGP well-known communities — implementation status

Audit of every well-known community constant defined in
`crates/bgp-packet/src/attrs/com.rs` (`CommunityValue`) against the
behavior its RFC prescribes. Last reviewed 2026-06-09, alongside the
change that added RFC 1997 egress suppression to the unicast / VPN /
EVPN outbound paths (`community_suppresses_advertisement` in
`zebra-rs/src/bgp/route.rs`).

| Community | Value | RFC | Status |
|---|---|---|---|
| NO_EXPORT | 0xFFFFFF01 | 1997 | **Enforced**: suppressed toward eBGP peers on IPv4/IPv6 unicast, VPNv4/VPNv6, labeled-unicast, and EVPN egress. SR Policy (SAFI 73) has its own RFC 9830 handling in `sr_policy.rs`. |
| NO_ADVERTISE | 0xFFFFFF02 | 1997 | **Enforced**: suppressed toward every peer on the same paths as NO_EXPORT. |
| NO_EXPORT_SUBCONFED (local-AS) | 0xFFFFFF03 | 1997 | **Enforced** as an alias of NO_EXPORT — BGP confederations are not implemented, so "do not advertise outside the member-AS" degenerates to "do not advertise to eBGP" (FRR behaves the same without confederations). |
| LLGR_STALE | 0xFFFF0006 | 9494 | **Enforced**: attached when stale-marking routes of an LLGR-negotiated session; routes *received* with the community are depreferenced like locally-marked stale routes (§4.3/§4.4 — the ingest paths OR it into `BgpRib.stale`); stale routes are not advertised to peers that did not send the LLGR capability (§4.3 — per-peer gate outside the update-group memo + an `llgr_ok` member filter at group-cache flush, counted in the `llgr_excluded` update-group counter), and the community is never stripped on re-advertisement. Remaining (pre-existing): the §4.6 partial-deployment MAY (advertise to non-LLGR iBGP peers with NO_EXPORT + LOCAL_PREF 0) is not implemented; the stale-retention machinery itself covers only VPNv4 and EVPN (no v4/v6-unicast, VPNv6, or labeled-unicast stale marking), and EVPN stale eviction on timer expiry is missing. |
| NO_LLGR | 0xFFFF0007 | 9494 | **Enforced** (§4.2): at stale-marking time, routes carrying NO_LLGR are not retained — they are removed from the Adj-RIB-In and withdrawn per normal RFC 4271 operation; only the remaining routes are stale-marked. |
| GRACEFUL_SHUTDOWN | 0xFFFF0000 | 8326 | Constant only. Future work: a `graceful-shutdown` knob that attaches the community + LOCAL_PREF 0 on egress, and lowers LOCAL_PREF on tagged ingress routes. Until then operators can match it in inbound policy. |
| ACCEPT_OWN | 0xFFFF0001 | 7611 | Constant only. Niche RR/VPN feature (accept routes carrying our own ORIGINATOR_ID across VRFs); unimplemented. |
| ACCEPT_OWN_NEXTHOP | 0xFFFF0008 | draft | Constant only; unimplemented. |
| BLACKHOLE | 0xFFFF029A | 7999 | Constant only. RFC 7999 handling (install discard route) is operator policy; a dedicated knob may come later. Matchable in policy today. |
| NO_PEER | 0xFFFFFF04 | 3765 | **Intentionally not enforced**: the community is advisory and "bilateral peer vs transit" cannot be determined automatically by the router; FRR does not enforce it either. Available to policy. |
| ROUTE_FILTER_TRANSLATED_V4 / ROUTE_FILTER_V4 / ROUTE_FILTER_TRANSLATED_V6 / ROUTE_FILTER_V6 | 0xFFFF0002-5 | — | Reserved constants (IANA registry); no standardized router behavior to implement. |

## Enforcement design notes

- The RFC 1997 gate runs in the shared outbound builders
  (`route_update_ipv4` / `route_update_ipv6` / `route_update_evpn`),
  **before** the per-peer outbound policy. A community the outbound
  policy itself attaches toward a peer therefore does not suppress that
  advertisement — only communities already on the route (received, or
  set at origination/ingress) do. FRR orders these the same way.
- The decision depends only on the peer *type* (iBGP/eBGP), which is
  part of `UpdateGroupSig`, so the result is uniform across an
  update-group and safe under the per-group advertise memo. Any future
  per-peer community rule (e.g. the LLGR capability gate) must be
  checked per-peer, outside that memo.
- IPv4 unicast / VPNv4 / EVPN get withdraw-on-transition for free: a
  suppressed route flows into `AdvertiseOutcome::Withdraw`, which is
  gated on the per-peer Adj-RIB-Out. The IPv6 egress has no Adj-RIB-Out
  yet, so v6 filtering is steady-state only (same pre-existing
  limitation as the deferred v6 outbound policy).
- BDD coverage: `bdd/tests/features/bgp_community.feature` — B has both
  an iBGP peer (C) and an eBGP peer (D), so NO_EXPORT (C yes / D no)
  and NO_ADVERTISE (neither) are each observable, including the
  withdraw and re-advertise transitions.
