# BGP MUP (Mobile User Plane) — deferred follow-ups

Status as of 2026-06-21. The MUP **control plane** (RFC 9833 /
draft-mpmz-bess-mup-safi, SAFI 85) landed on branch `bgp-mup` over four
phases, committed and pushed (rebased onto `origin/main`):

- **P0 codec** — completed the `MupRoute` codec to be GoBGP byte-exact:
  T1ST now emits the mandatory source-address-length octet + optional
  `source`; T2ST remodeled `IpNet` → `{endpoint, endpoint_len, teid}`
  (length up to 64/160, high-aligned TEID). GoBGP byte-exact interop
  vectors added. The MUP Extended Community (`0x0c`) and SAFI 85 were
  already present.
- **P1 negotiation** — `mobile-uplane` afi-safi knob that expands to
  *both* `(Ip, Mup)` and `(Ip6, Mup)` capabilities (`mp_family_expand`),
  per-neighbor and per-group.
- **P2 Loc-RIB + receive + show** — full-NLRI `MupPrefix` key + flat
  `LocalRibMupTable`; `route_mup_update`/`route_mup_withdraw` wired into
  the `MpReachAttr::Mup` / `MpUnreachAttr::Mup` receive arms; `adj_in.mup`;
  `route_clean` peer-down; `show bgp mobile-uplane` route table.
- **P3 per-VRF config** — `router bgp vrf <name> mobile-uplane`:
  `route-target export` + `srv6-mobile {decapsulation|encapsulation}
  network-instance exact <ni>`; the config-driven `MUP VRFs:` block in
  `show bgp mobile-uplane`.
- **P4 advertise / re-originate** — `MupPrefix::afi()`/`to_route()`,
  `adj_out.mup`, AFI-aware `route_advertise_mup_to_peers` /
  `route_withdraw_mup_to_peers` (EVPN suppression + eBGP-next-hop-self /
  iBGP-preserve + LLGR gate; next-hop in MP_REACH), and the
  establish-time `route_sync_mup` replay + per-AFI EoR.

Tests on the rebased base: 342 `bgp-packet` + 1378 `zebra-rs`, fmt +
workspace clippy clean.

The items below were consciously left out so each phase could ship as a
small PR. None block the control-plane path for the common case
(receive / store / show / re-advertise MUP routes between speakers).
Each entry: **what / why deferred / where / suggested PR size**. The
two large remaining phases (P5 controller, P6 dataplane) are at the end
with their open design questions.

Standing guidance still applies: smallest meaningful slice first, let
the user redirect, one branch / one PR at a time.

## Receive / Loc-RIB

### 1. Inbound route-policy for MUP

**What:** Received MUP routes are stored unfiltered — no per-AFI inbound
`policy`/`prefix-set` is applied in `route_mup_update`.

**Why deferred:** No per-AFI MUP policy binding exists (the `afi-safi
<name> policy {in,out}` / `prefix-set` knobs don't yet accept
`mobile-uplane`). Parity with EVPN, which also applies no inbound policy.

**Where:** `route_mup_update` in `zebra-rs/src/bgp/route.rs`; the per-AFI
policy plumbing in `zebra-rs/src/bgp/config.rs` (`config_afi_safi_policy_*`)
+ `Peer::policy_list_at`. See [the per-AFI policy work](bgp-multiprotocol-receive-followups.md).

**Size:** medium (~250 lines: policy binding + apply + tests).

### 2. Next-Hop Tracking (NHT) for MUP next-hops

**What:** The MUP next-hop (PE/controller IPv6 address) is not registered
with NHT, so reachability/recursive-resolution gating isn't applied to
MUP routes.

**Why deferred:** P2/P4 are control-plane only; the NHT gate matters once
MUP routes drive forwarding (P6) or feed the controller's resolution.

**Where:** `route_mup_update` + the NHT register/gate path
(`zebra-rs/src/bgp/nht*`), mirroring how VPNv4/VPNv6 next-hops register.

**Size:** medium (~200 lines).

### 3. VRF import (route-target → VRF) for received MUP routes

**What:** The per-VRF `mobile-uplane route-target export` set (P3) is
stored but there is no import dispatch that pulls received MUP routes
into a VRF by RT (unlike VPNv4/EVPN's `VrfImportDispatcher`).

**Why deferred:** MUP "import" semantics are session-shaped (ST routes
map to GTP tunnels), not L3VPN-prefix-shaped; the consumer is the P5
controller / P6 dataplane, which don't exist yet.

**Where:** mirror `dispatch_import_*` in `zebra-rs/src/bgp/route.rs` once
the controller defines what importing an ST route *means*.

**Size:** medium-large (design-dependent; sequence after P5).

### 4. RFC 7606 treat-as-withdraw coverage for MUP

**What:** The NLRI decoder already treat-as-withdraws malformed MUP NLRI
fields (bad prefix/endpoint length, zero TEID, etc.). Confirm the
*attribute*-level path — `withdraw_mp_reach` / the `treat_as_withdraw`
branch in `route_from_peer` — has a MUP arm, so a malformed-attribute
UPDATE that rides alongside a MUP NLRI withdraws the reachable NLRI
rather than leaving an installed copy.

**Why deferred:** Same gap flagged generally for all newly-surfaced
families in [`bgp-multiprotocol-receive-followups.md`](bgp-multiprotocol-receive-followups.md) §"RFC 7606".

**Where:** `withdraw_mp_reach` in `zebra-rs/src/bgp/route.rs`.

**Size:** small (~80 lines + test).

### 5. LLGR stale-retention on peer-down

**What:** `route_clean`'s MUP block is a simple non-LLGR withdrawal. The
advertise side already honours LLGR (`llgr_blocks_advertisement` gates
`mup_advertise_one` / `route_sync_mup`), but on peer-down MUP routes are
withdrawn outright rather than stale-marked + retained for the LLGR
stale time.

**Why deferred:** LLGR for MUP is niche; the two-branch
stale-mark/retain path (EVPN/VPNv4 have it) is extra surface for a
control-plane-first phase.

**Where:** the MUP block in `route_clean` (`zebra-rs/src/bgp/route.rs`);
mirror the EVPN LLGR two-branch.

**Size:** medium (~200 lines).

## Show

### 6. Full `MUP controller:` show block

**What:** `show bgp mobile-uplane` renders the config-driven `MUP VRFs:`
block (P3) + the route table (P2). The mockup's full wrapper — header
`MUP controller: enabled`, the `zenoh source:` line, `ingested sessions`
count, and the `vpnv6 ue-routes:` list — needs P5 controller state.

**Why deferred:** Those lines describe controller runtime that doesn't
exist until P5.

**Where:** `show_bgp_mup` / `render_mup_vrfs` in `zebra-rs/src/bgp/show.rs`.

**Size:** small once P5 state exists (~150 lines).

### 7. `show bgp mobile-uplane` JSON output

**What:** The JSON branch returns the `"[]"` placeholder; only text is
implemented.

**Why deferred:** Text sufficed on landing.

**Where:** `show_bgp_mup` in `zebra-rs/src/bgp/show.rs`.

**Size:** small (~120 lines).

## Advertise (P4)

### 8. Egress coalescing / update-groups for MUP

**What:** `route_advertise_mup_to_peers` sends one MP_REACH per route per
peer via direct `send_packet` (the flowspec shape) — no update-group
batching or `UpdateGroupSig` membership.

**Why deferred:** Correct on the wire; coalescing is a scale
optimization, and building a MUP egress-cache layer is its own work.

**Where:** `mup_send_one` / `route_advertise_mup_to_peers` in
`zebra-rs/src/bgp/route.rs`. See [`bgp-update-groups.md`](bgp-update-groups.md).

**Size:** medium (~300 lines).

### 9. Per-AFI MUP outbound route-policy

**What:** Egress passes unfiltered — no `policy_list_apply` on the MUP
advertise path.

**Why deferred:** No MUP policy binding exists (see #1); parity with EVPN
when no Output policy is configured.

**Where:** `mup_advertise_one` in `zebra-rs/src/bgp/route.rs`.

**Size:** medium (pairs with #1).

### 10. MUP AddPath TX

**What:** Fan-out uses `established_plain_idents` (best path only); no
Add-Path send, and withdraw is the id-less whole-prefix MP_UNREACH.

**Why deferred:** Add-Path TX isn't implemented for MUP; plain best-path
covers the controller→PE and RR cases.

**Where:** `route_advertise_mup_to_peers` + `adj_out.mup` (give the table
an Add-Path id dimension like the v4 path).

**Size:** medium (~250 lines).

### 11. eBGP next-hop-self next-hop family

**What:** For eBGP / originated routes, `route_update_mup` sets the
next-hop to `peer.param.local_addr.ip()`, which may be IPv4. RFC 9833
next-hops are IPv6 (PE/controller address).

**Why deferred:** iBGP / route-reflector — the common controller→PE path
— *preserves* the received IPv6 next-hop, so this only affects eBGP MUP
peering, which is unusual.

**Where:** the next-hop branch in `route_update_mup`
(`zebra-rs/src/bgp/route.rs`); force a v6 next-hop-self for MUP.

**Size:** small (~60 lines).

## Codec / model

### 12. BGP-IP-VPN architecture type (arch 2)

**What:** Only architecture type 1 (`3gpp-5g`) is decoded into typed
fields; any other architecture type falls through to `MupRoute::Unknown`
(opaque body, round-trip preserved).

**Why deferred:** 3GPP-5G is the only architecture the draft fully
specifies and the only one deployed.

**Where:** `crates/bgp-packet/src/attrs/nlri_mup.rs`
(`MupArchitectureType` + the per-route-type bodies).

**Size:** medium (only if a non-3GPP architecture is ever needed).

### 13. Strict draft route-key (vs the chosen full-NLRI key)

**What:** The RIB keys on the *whole* NLRI (minus the Add-Path id). The
draft's route-key for BGP best-path is narrower — `RD + Prefix` for
T1ST, `RD + Endpoint + TEID` for T2ST — i.e. a newer T1ST for the same
UE prefix would *replace* an older one even if the TEID differs.

**Why deferred:** Full-NLRI key is simpler, makes `show` complete
directly, and relies on explicit withdraws (normal BGP). The strict
route-key needs per-path TEID/QFI/endpoint/source stored off-key on
`BgpRib` for display. Chosen deliberately; revisit only if
implicit-replace semantics are required.

**Where:** `MupPrefix` in `crates/bgp-packet/src/attrs/nlri_mup.rs`.

**Size:** medium (~300 lines: off-key path fields + show plumbing).

## Testing

### 14. End-to-end receive-from-peer / RR BDD

**What:** A multi-node BDD (originate on one speaker, receive +
re-advertise + show on another) that exercises the full control plane on
the wire.

**Why deferred:** The BDD harness is zebra-rs↔zebra-rs (no GoBGP/ExaBGP
injector), so an *originator* is required — and MUP origination is P5.
`bdd/tests/features/bgp_mup_capability.feature` (session-up + capability
negotiation) is authored but **not run** (needs root netns; BDD is
excluded from CI gates per
[`zebra-rs-ci-and-merge-rules`](../../zebra-rs-ci-and-merge-rules.md)).

**Where:** `bdd/tests/`.

**Size:** medium (lands with P5).

### 15. zebra-rs-level advertise integration test

**What:** No test drives `route_mup_update` → `adj_out.mup` + emitted
MP_REACH through a full `Bgp` + Established peer.

**Why deferred:** Standing up a full `Bgp` + peer + membership is
impractical as a unit test (EVPN's advertise isn't unit-tested either).
Coverage today is compile + clippy-wiring + the `bgp-packet`
`afi()`/`to_route()` and `MupPrefix` tests + the `render_mup_*` tests.

**Where:** `zebra-rs/src/bgp/route.rs` test module (or a harness).

**Size:** medium.

## The two remaining phases

### P5 — MUP Controller (zenoh / PFCP)

**What:** Subscribe to PFCP sessions over zenoh and originate, per
session: an ST1 route (the `encapsulation` / N6 VRF), an ST2 route (the
`decapsulation` / N3 VRF), and a VPNv6 UE route — each tagged with the
VRF's `route-target export` and an SRv6 SID — plus the full
`MUP controller:` show block (zenoh source, ingested-session count,
originated-route count, `vpnv6 ue-routes`).

**Open design questions (need operator input before building):**
1. **Session schema** on the zenoh `pfcp/**` keys — encoding (JSON /
   protobuf / custom) and fields (UE prefix, TEID, QFI, gNodeB endpoint,
   source, network-instance, …). This is the blocker for the
   session→route mapping.
2. **`zenoh` crate** dependency + the `zenoh source tcp/<addr>:<port>` /
   `prefix pfcp/**` config knobs (and a pinned version).
3. **SID source** — where ST / VPNv6 SIDs come from (the mockup shows
   `sid=fcbb:bb00:30:19::`, i.e. carved from a global `srv6 locator`
   like the L3VPN End.DT46 path).

**Recommended seam:** a `SessionSource` trait (zenoh is one impl) so the
session→ST origination logic is unit-testable without standing up a
zenoh bus. This also unblocks the end-to-end BDD (#14) using a synthetic
source.

**Where:** new module under `zebra-rs/src/bgp/`; origination reuses the
P4 advertise path + the VPNv6 origination path.

**Size:** large (multi-PR).

### P6 — SRv6-mobile dataplane

**What:** Install the FIB state for MUP-derived routes. Per the chosen
"install what the kernel supports" scope: program `End.DT4/6` + the
route-level SIDs we already do for L3VPN/SRv6, and flag the GTP
behaviours (`End.M.GTP4.E` / `End.M.GTP6.E` / `GTP4.E` / `GTP6.E`) as
needing VPP or eBPF — mainline Linux `seg6local` has no `End.M.GTP*`
actions. See the kernel-support note in
[`bgp-prefix-sid-rfc9252.md`](bgp-prefix-sid-rfc9252.md) and
[`srv6-l3vpn` forwarding notes](../../zebra-rs-srv6-l3vpn-forwarding-bugs.md).

**Where:** the FIB install path + `seg6local` programming.

**Size:** large.

## Quick-pick recommendations

By value-per-line, if picking one up independently of P5/P6:

1. **#7 (`show bgp mobile-uplane` JSON)** — cheap, mechanical, zero risk.
2. **#11 (eBGP v6 next-hop-self)** — small RFC-correctness fix.
3. **#4 (RFC 7606 attr-level treat-as-withdraw for MUP)** — closes a
   small correctness/robustness gap on malformed UPDATEs.
4. **#1 + #9 (per-AFI MUP inbound + outbound policy)** — do together;
   first thing a real deployment with filtering will need.

Larger items (#3 VRF import, #8 update-groups, #10 AddPath TX, #13
strict route-key) should each gate on a concrete consumer — most of them
naturally sequence after **P5**, which is the next real milestone (and
needs the operator design input above before it can start).

## Cross-references

- [`bgp-multiprotocol-receive-followups.md`](bgp-multiprotocol-receive-followups.md)
  — the parse-layer enabler that first surfaced MUP on receive; its
  RFC 7606 and `route_sync_*` notes apply here too.
- [`bgp-prefix-sid-rfc9252.md`](bgp-prefix-sid-rfc9252.md) — SRv6 SID /
  Prefix-SID codec and the kernel `seg6local` support boundary relevant
  to P6.
- [`bgp-flowspec-plan.md`](bgp-flowspec-plan.md) — the exact-match,
  control-plane-first, per-route-`send_packet` AFI the MUP advertise path
  mirrors.
- EVPN was the structural template throughout (exact-match Loc-RIB,
  receive dispatch, advertise, establish-sync) — see the EVPN plan docs.
