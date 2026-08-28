# BGP Route Server mode (RFC 7947) — design

Status: **implemented 2026-08-28** on branch `bgp-route-server` (one PR, as
sized below): knob + inheritance + VRF, `EgressAs.route_server_client`
early-return in `ebgp_egress_aspath`, next-hop-unchanged implied for
forwarded unicast rows (v4 via `sync_ctx`, v6 in the builder),
`UpdateGroupSig.route_server_client` (SIGNATURE_VERSION 8), show, BDD
`bgp_route_server.feature` on a bridged LAN, book `ch-02-43`. Deviations
from §3.2: incompatible AS_PATH knobs are *ignored with a warning* rather
than rejected in the callback (callback order within a commit makes
rejection unreliable); a change bounces the live session so the client
re-receives the table in the new form.

Originally split out of the RFC 9234 plan (`bgp-rfc9234-plan.md`) so the
OTC work could land first.

## 1. Why

An Internet Exchange route server (RFC 7947) re-advertises its clients'
routes to each other *transparently*: it does not prepend its own AS, does
not rewrite NEXT_HOP, and passes MED and communities through unchanged, so a
client sees exactly the path the originating member sent. zebra-rs has no
such mode today. The RFC 9234 role `route-server` / `route-server-client`
pair also only becomes meaningful once zebra-rs can be the RS.

## 2. Current state (verified 2026-08-28)

| RFC 7947 requirement | zebra-rs today |
|---|---|
| §2.2.1 NEXT_HOP unchanged | available per AFI: `afi-safi ipv4\|ipv6 next-hop-unchanged` (`SyncCtx.unicast_next_hop_unchanged`, `Peer::next_hop_unchanged`) |
| §2.2.2 AS_PATH transparent (no RS AS prepend) | **missing** — `route.rs::ebgp_egress_aspath` prepends unconditionally for every eBGP peer (9 call sites; only the v4/v6 unicast ones matter here) |
| §2.2.2.1 MED passthrough | already passthrough (`route_update_ipv4` "4. MED - Pass through") |
| §2.2.2.2 communities passthrough | already passthrough |
| §2.3 path hiding — §2.3.2.2 ADD-PATH | ADD-PATH **send** implemented for v4/v6 unicast (`cap::addpath_send_implemented`) |
| §2.3 path hiding — §2.3.2.1 per-client Loc-RIB | not implemented; **not planned** (ADD-PATH covers it) |
| client fan-in | `listen-range` dynamic neighbors, per-neighbor in/out policy, `enforce-first-as` (must be OFF on the *client* side toward an RS) |
| book | `appendix-b-supported-rfcs.md:36` lists RFC 7947 as supported (commit f3f39061) — **not backed by code**; correct it or make it true here |

No `route-server-client` knob, no RS-side attribute-transparency switch exists.

## 3. Design

### 3.1 Knob
`neighbor <X> route-server-client` — presence container, FRR/BIRD spelling
(Cisco IOS XR has no route-server function, so there is no XR syntax to
match). Module `zebra-bgp-route-server.yang`, prefix `zbrs`, grouping
`bgp-neighbor-route-server-client-extension`; `uses` in
`zebra-bgp-neighbor-group.yang` (inheritable — an IXP configures one group
for all members), inline container in `zebra-bgp-vrf.yang`. Parse test in
`config/manager.rs` before anything else (memory
`zebra-rs-bgp-neighbor-yang-ietf-collision`: check `ietf-bgp-common` for a
same-named leaf first; grep today shows none).

### 3.2 Egress transform (v4/v6 unicast only)
* `PeerConfig.route_server_client: bool` → `EgressAs.route_server_client`.
* `ebgp_egress_aspath`: return early when set — no local-AS prepend. The
  transforms it would otherwise run (`remove-private-as`, `as-override`,
  `local-as` substitute) are incompatible with a transparent RS: reject the
  combination in the config callback (clearest) rather than silently
  skipping.
* NEXT_HOP: treat forwarded rows as `next-hop-unchanged` (OR the flag into
  `unicast_next_hop_unchanged` in `Peer::sync_ctx` and the v6 builder's
  `nh_unchanged`). Locally-originated rows still rewrite to self.
* MED / communities / AIGP: nothing to do.
* **`UpdateGroupSig.route_server_client`** + `SIGNATURE_VERSION` bump — an
  RS client must never share canonical bytes with an ordinary eBGP peer
  (memory `zebra-rs-bgp-update-group-signature-trap`); extend
  `signature_fields_each_distinguish`.
* Other families (labeled, VPN, EVPN, …): untouched, still prepend.

### 3.3 Ingress
Ordinary eBGP. The RS AS never appears in a client's AS_PATH, so the RFC
4271 loop check is unaffected. Best-path selection stays global (one
Loc-RIB); with `add-path send` on the client sessions every member path is
advertised, which is the RFC 7947 §2.3.2.2 answer to path hiding.

### 3.4 Interplay with RFC 9234 (once both exist)
`otc-local-role route-server` on the RS, `route-server-client` on members:
* RS: ER1 stamps `OTC-AS: <RS AS>` toward clients; IR1 rejects an
  OTC-marked route received from a client.
* Client: IR3 stamps OTC = RS AS when absent; ER2 blocks OTC-marked routes
  toward the RS.
* OTC carries the **RS's** AS, not the originating member's — RFC 9234 §5
  as written; document it.

### 3.5 Show / docs / tests
* `show bgp neighbor` (text + JSON): "Route-server client: yes".
* BDD `bgp_route_server.feature`: RS AS65000 with clients AS65001 and
  AS65002 (three namespaces on one bridge or two P2P links). Client 2
  receives 65001's prefix with AS_PATH `65001` (no 65000) and the original
  next-hop; a control scenario without the knob shows `65000 65001`.
  Optional: `add-path send` scenario with two members announcing the same
  prefix. Later: RS↔RS-client OTC scenario.
* Book `ch-02-43-bgp-route-server.md`; fix the appendix-b row; changelog.

## 4. Out of scope
* Per-client Loc-RIB (§2.3.2.1).
* RS-side per-client export policy language beyond the existing route-map /
  prefix-set / community machinery.
* IRR/RPKI-driven filtering (separate feature).

## 5. Estimated size
One PR: YANG + callback/inheritance wiring, ~20 lines in `route.rs` /
`update_group.rs`, show, one BDD feature, book chapter. Comparable to
`enforce-first-as` (PR of 2026-06-08) plus the update-group sig change.
