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
- **P1 negotiation** — `mup` afi-safi knob that expands to
  *both* `(Ip, Mup)` and `(Ip6, Mup)` capabilities (`mp_family_expand`),
  per-neighbor and per-group.
- **P2 Loc-RIB + receive + show** — full-NLRI `MupPrefix` key + flat
  `LocalRibMupTable`; `route_mup_update`/`route_mup_withdraw` wired into
  the `MpReachAttr::Mup` / `MpUnreachAttr::Mup` receive arms; `adj_in.mup`;
  `route_clean` peer-down; `show bgp mup` route table.
- **P3 per-VRF config** — `router bgp vrf <name> mup route {st1|st2}
  dest-network-instance {access|core} exact <ni>` (the ST origination
  binding), plus the export/import route-targets on the top-level
  `vrf <name> mup route-target {export|import}` (RIB-owned, the same
  framework as ipv4 / ipv6, surfaced to BGP via `rib_known_vrfs`); the
  config-driven `MUP VRFs:` block in `show bgp mup`.
- **P4 advertise / re-originate** — `MupPrefix::afi()`/`to_route()`,
  `adj_out.mup`, AFI-aware `route_advertise_mup_to_peers` /
  `route_withdraw_mup_to_peers` (EVPN suppression + eBGP-next-hop-self /
  iBGP-preserve + LLGR gate; next-hop in MP_REACH), and the
  establish-time `route_sync_mup` replay + per-AFI EoR.

Tests on the rebased base: 342 `bgp-packet` + 1378 `zebra-rs`, fmt +
workspace clippy clean.

**P5 (the MUP Controller) is now built** over PR-A/B/C using a **PFCP/N4**
northbound (not zenoh) — see the P5 section below. **P6 (the
SRv6-mobile dataplane) remains the one large deferred phase.**

The items below were consciously left out so each phase could ship as a
small PR. None block the control-plane path for the common case
(receive / store / show / re-advertise MUP routes between speakers, and
controller origination). Each entry: **what / why deferred / where /
suggested PR size**; several are now marked **DONE** by P5.

Standing guidance still applies: smallest meaningful slice first, let
the user redirect, one branch / one PR at a time.

## Draft-default forwarding & mixed-AFI (2026-06-23)

Two post-P5 corrections aligned the controller and codec with
draft-ietf-bess-mup-safi (merged as PR #1614):

**No SID allocation by the controller — draft-default forwarding.** The
MUP-C no longer allocates or advertises an SRv6 service SID on the ST
routes it originates. Per the draft the **default** is that the receiving
PE derives the forwarding SID from its *own* ISD / DSD routes: it matches
an ST route against the segment a co-located ISD (GTP4.E / GTP6.E) or DSD
(End.DT4/6) route advertises and programs the FIB itself. So an
originated ST route now carries only the controller-address next hop and
the VRF's route-target exports — `alloc_mup_sid` / `mup_sid_behavior` and
the per-session SID-function bookkeeping were removed, and
`build_mup_attr` no longer attaches the SRv6 L3 Service Prefix-SID.
Carrying an *explicit* SID (via Prefix-SID or the `0x0c` MUP Direct-SID
extended community) is the **non-default, controller-pushed** mode; it
can be reintroduced behind a knob if a deployment needs it, and the
now-unused `mup-c srv6 locator` config is retained as the natural home
for that mode.

**Mixed-AFI T1ST endpoint/source.** A Type-1 ST route's endpoint (gNB)
and source (UPF) address family is now decided by its own length octet
(32 = IPv4, 128 = IPv6), **independent of the outer AFI**; only the UE
prefix follows the outer AFI. This lets an IPv6 UE route carry an IPv4
gNB/UPF — the real 5G case where the N3 transport is IPv4 — matching
GoBGP. (T2ST keeps its single endpoint AFI-tied; it has no second address
that could differ.) Covered end-to-end by the `@bgp_mup_mixed_afi` BDD
feature (#14): an IPv6 UE + IPv4 endpoint session, with no SRv6 locator
configured anywhere, originated by z1 and received/parsed by z2.

## CLI rename, RT framework, per-VRF show (2026-06-23)

Three follow-on changes (post-PR #1614, not yet merged):

**`mobile-uplane` → `mup` rename.** The CLI / YANG keyword is now `mup`
everywhere: the afi-safi enum (`neighbor X afi-safi mup`,
`router bgp afi-safi mup mup-c`), `show bgp mup`, `router bgp vrf <name>
mup`, and every matching callback-path string + YANG node name (renamed
in lockstep). Internal Rust identifiers (`mobile_uplane`,
`BgpVrfMobileUplane`, `MupSrv6*`) are unchanged — not user-facing.

**Export RT moved to the top-level VRF framework.** The MUP export (and
import) route-targets now live on `vrf <name> mup route-target
{export|import}` — the same `vrf-route-target-policy` grouping as
`ipv4` / `ipv6`, owned by the RIB. They flow RIB → BGP via
`Message::VrfRouteTargets` / `RibRx::VrfRouteTargets`
(`mup_{import,export}_rts`) into `RibKnownVrf`, and `build_mup_origination`
reads the export set from `rib_known_vrfs`. **Consequence:** the MUP RT
now requires the VRF's kernel device to exist (it rides the RIB `Vrf`
row), exactly like the ipv4/ipv6 RT — the old `router bgp vrf <name> mup
route-target export` is gone. The import set is parsed and carried but
not yet consumed (reserved for the MUP import dispatch, §3 below).

**`show bgp vrf <name> mup`.** The MUP Loc-RIB is global, but the
command renders per-VRF: the global `mup_apply_selected` mirrors each
best-path to the per-VRF `BgpVrf` task whose `rd` matches the route's RD
(`BgpVrfMsg::Mup{Update,Withdraw}`, display-only — it touches just
`local_rib.mup.selected`). The manager's existing `vrf_redirect_split`
routes `show bgp vrf <name> mup` into that task, which renders it via the
new `/show/bgp/mup` arm in `process_vrf_show` (`show_bgp_vrf_mup`). The
per-VRF task spawns from `router bgp vrf <name>` config (placeholder
context when the kernel VRF isn't up yet), so the redirect target exists.
A `/show/bgp/vrf/mup` global handler is the not-running fallback.

## Receive / Loc-RIB

### 1. Inbound route-policy for MUP

**What:** Received MUP routes are stored unfiltered — no per-AFI inbound
`policy`/`prefix-set` is applied in `route_mup_update`.

**Why deferred:** No per-AFI MUP policy binding exists (the `afi-safi
<name> policy {in,out}` / `prefix-set` knobs don't yet accept
`mup`). Parity with EVPN, which also applies no inbound policy.

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

**What:** The per-VRF `mup route-target export` set (P3) is
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

### 6. Full `MUP controller:` show block — **DONE (P5)**

`show bgp mup mup-c [session|association]` now renders the
controller runtime (admin state, PFCP listen address, association /
session counts, and the per-session table) from the BGP-held
`mup_c_view` the controller feeds over `Message::MupC`. The
`zenoh source:` line is moot (the northbound is PFCP, not zenoh); the
`vpnv6 ue-routes:` list was dropped (the ST routes carry the SRv6
service directly). `show bgp mup` still renders the `MUP VRFs:`
block (P3) + the route table (P2), now populated by originated ST routes.

**Where:** `show_bgp_mup_c*` / `render_mup_vrfs` in `zebra-rs/src/bgp/show.rs`.

### 7. `show bgp mup` JSON output

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

### 14. End-to-end originate → receive BDD — **DONE (P5/PR-C)**

`bdd/tests/features/bgp_mup_e2e.feature` (`@bgp_mup_e2e`): the controller
node (z1) is driven by `tools/pfcp-inject` (a PFCP SMF simulator that
supplies the originator the harness otherwise lacks), originates the ST1
route, and the peer (z2) receives it. The earlier
`bgp_mup_capability.feature` covers session-up + capability negotiation.
`bgp_mup_mixed_afi.feature` (`@bgp_mup_mixed_afi`) is a variant covering
the *Draft-default forwarding & mixed-AFI* corrections above — an IPv6 UE
with an IPv4 endpoint, originated with no SRv6 locator configured, and
parsed by the peer under the IPv6-MUP AFI. All need root netns and are
excluded from CI gates per
[`zebra-rs-ci-and-merge-rules`](../../zebra-rs-ci-and-merge-rules.md) —
run live (`make -C bdd bgp_mup_e2e` / `make -C bdd bgp_mup_mixed_afi`,
with `pfcp-inject` staged on PATH). Remaining: a receive-from-peer / RR
variant (a third node reflecting the ST route) is still worth adding.

**Where:** `bdd/tests/features/bgp_mup_e2e.feature`, `tools/pfcp-inject/`.

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

### P5 — MUP Controller (PFCP) — **BUILT**

Built over PR-A/B/C. The northbound is **PFCP / N4** (3GPP TS 29.244, via
the `rs-pfcp` crate), not zenoh — the controller terminates N4 as a
UP-node, so an external SMF programs it exactly as it would a UPF. The
session schema question is therefore answered by PFCP itself (no custom
zenoh encoding to design).

* **Config home:** directly under the BGP instance at `router bgp mup-c {
  enable; controller-address; pfcp {…}; srv6 {…} }` (lifted out of the
  former `afi-safi mup` wrapper) — so the controller is spawned by the BGP
  task and handed its `Message` channel, the way a per-VRF BGP instance is.
  Module: `zebra-rs/src/mup-c/`
  (`inst` task, `pfcp` socket/handlers, `session`/`assoc` tables); spawn /
  reconfigure / teardown in `Bgp::apply_mup_c_commit_diff`.
* **PR-A (ingest):** PFCP listener (own tokio UDP socket); Association
  Setup/Release, Heartbeat, Session Establishment/Modification/Deletion;
  per-session table; `show bgp mup mup-c [session|association]`.
  Hardened (commit security review): session-ownership check on
  Modify/Delete, association precondition on Establish, bounded tables.
* **PR-B (origination):** `Bgp::originate_mup_route` correlates the
  session's Network Instance → a per-VRF `mup` config (RD /
  route-targets / `route {st1|st2}` direction), builds the ST NLRI
  (`st1`→T1ST UE prefix; `st2`→T2ST endpoint+TEID) and attributes
  (controller-address next hop, RT exports), and originates via the P4
  advertise path. Tracked per session SEID for stable withdraw. As of
  2026-06-23 it allocates **no** SRv6 SID — see *Draft-default
  forwarding* above. (PR-B as originally landed did allocate an
  End.DT4/6 Prefix-SID; that was removed to match the draft default.)
* **PR-C (e2e):** `tools/pfcp-inject` (PFCP SMF simulator) + the
  `@bgp_mup_e2e` BDD feature (#14). Live-validated end-to-end.

**Deferred from P5:** the VPNv6 UE host route originally listed here was
dropped. Heartbeat-driven eviction of idle PFCP associations and
per-source rate limiting are follow-ups (the tables are bounded by hard
caps today). The controller-pushed *explicit*-SID origination mode (and
its `mup-c srv6 locator` source) is a follow-up — the default is now
PE-derived forwarding, see *Draft-default forwarding* above.

### P6 — SRv6-mobile dataplane

#### P6 slice 1 — DSD origination + End.DT46 (2026-06-23) — **DONE**

The first P6 slice landed the **PE-side Direct Segment Discovery (DSD,
type 2) origination** that the draft-default ST routes resolve against:

- **`afi-safi mup segment {direct|interwork}`** on a per-VRF BGP block
  (zebra-bgp-vrf.yang, under the per-VRF `afi-safi` container — distinct
  from the controller-side `mup route {st1|st2}`). `MupSegmentMode` on
  `BgpVrfMobileUplane`; callback `/router/bgp/vrf/afi-safi/mup/segment`.
  `interwork` (ISD, type 1) is parsed but origination is deferred.
- **`segment direct` originates a DSD** route for the VRF: NLRI is the
  VRF **RD + router-id** (so it rides the IPv4-MUP AFI); the attributes
  carry the PE locator node as the **IPv6 next-hop** and the per-VRF
  **End.DT46 SID** as the SRv6 L3 Service (`srv6_l3_service_prefix_sid`,
  `SRV6_BEHAVIOR_END_DT46`). `build_mup_dsd_origination` /
  `originate_mup_dsd` / `withdraw_mup_dsd` mirror the controller ST path;
  `reconcile_mup_dsd` is the idempotent driver.
- **SID + FIB install are pure reuse** of L3VPN-over-SRv6: a VRF with
  `encapsulation srv6` already carves an End.DT46 SID (`alloc_vrf_sid`)
  and installs the `seg6local End.DT46 SEG6_LOCAL_VRFTABLE(table_id)`
  decap at spawn. The DSD path only *reads* `vrf_registry[name].srv6_sid`
  and advertises it — no new alloc / FIB code.
- **Gating + reconcile triggers:** the DSD originates only once the VRF
  has `segment direct` + `encapsulation srv6` + an RD + a resolved SID +
  a **known kernel VRF** (proxy for "End.DT46 is installed") + a non-zero
  router-id. `reconcile_mup_dsd` runs from `apply_vrf_commit_diff`,
  `maybe_respawn_vrf_with_kernel_ctx` (kernel-ctx / FIB install),
  `reconcile_srv6_vrfs` (locator-driven SID change under a stable key),
  the `VrfDel` and MUP-RT (`VrfRouteTargets`) handlers, and `set_router_id`
  (the router-id is in the NLRI key). `route_update_mup` advertises the
  attr IPv6 next-hop for originated routes carrying a Prefix-SID (DSD);
  ST routes (no Prefix-SID) are unaffected.
- **Show:** `show bgp mup` / `show bgp vrf <name> mup` now print the SRv6
  L3 SID line (`Local/Remote SID <sid> (End.DT46)`).
- **Test:** `@bgp_mup_segment_dsd` BDD (root) — z1 originates the DSD,
  installs the `seg6local End.DT46` (asserted via `ip -6 route show table
  all`), and z2 receives it with the SID. Excluded from CI; run live via
  `make -C bdd bgp_mup_segment_dsd`.

**Still open in P6:** the *receive* side — a PE consuming a peer's DSD/ISD
route to drive forwarding (the *ISD/DSD-route → segment-SID resolution*
step below), ISD (`segment interwork`) origination, and the GTP
behaviours.

#### P6 slice 2 — ST2 origination (TEID) + MUP Extended Community — **DONE**

Corrected and completed the controller-side **Type-2 Session-Transformed
(ST2)** origination from a PFCP decapsulation session, and added the BGP
MUP Extended Community:

- **TEID encoding fix.** The MUP-C was setting the T2ST *Endpoint Length*
  to the bare address width (32 / 128), which made the codec emit **zero
  TEID octets** — a malformed NLRI per draft-mpmz-bess-mup-safi §3.1.4.1
  ("a TEID value of 0 is considered invalid"). It is now `64` (IPv4) /
  `160` (IPv6) = the address bits plus the full 32-bit GTP TEID, matching
  the GoBGP byte-exact vectors. `build_mup_origination`
  (`zebra-rs/src/bgp/route.rs`).
- **BGP MUP Extended Community** (transitive type `0x0c`, sub-type `0x00`
  = Direct-Type Segment Identifier, §3.2). New per-VRF knob `router bgp
  vrf <name> afi-safi mup segment direct mup-ext-comm <2:4>` (YANG leaf
  `mup-ext-comm`, type `route-distinguisher`; `BgpVrfMobileUplane
  .mup_ext_comm`). The 6-octet value reuses the RD/RT 2:4 wire layout. It
  is attached to the **ST2** route the controller originates (§3.3.10 —
  the Direct segment a receiving PE resolves against, §3.3.12) and to the
  VRF's **DSD** route (it *is* that Direct segment). End.DT46 is the
  forwarding behaviour both directions (RFC 9433), so no SID is carried —
  the ext-comm is the correlation handle.
- **Show.** `show bgp mup` / `show bgp vrf <name> mup` render the Direct
  segment id bare in the RD/RT 2:4 form on the ext-community line (e.g.
  `RT:65000:200 1:2`).
- **DSD re-origination fix.** `reconcile_mup_dsd` skipped re-origination
  whenever the NLRI key + SID were unchanged, so a DSD that originated
  before its export route-target arrived (asynchronously, via
  `VrfRouteTargets`) never carried the RT — and would likewise miss a
  later `mup-ext-comm`. The skip now also compares the ext-community set,
  so an RT / segment-id change re-advertises under the stable key.
- **Grammar simplification.** The ST2 (uplink) Network-Instance binding
  moved off the nested `router bgp vrf <name> mup route st2
  dest-network-instance core exact <ni>` onto a single
  `router bgp vrf <name> afi-safi mup network-instance <ni>` leaf, next to
  `segment direct` (the Direct segment the ST2 resolves to). It still maps
  to the Decapsulation direction on `srv6_mobile`, so `build_mup_origination`
  / `render_mup_vrfs` are unchanged. The downlink `mup route st1
  dest-network-instance access exact <ni>` is unchanged; the `route st2`
  sub-container was removed.
- **Tests.** `@bgp_mup_st2` BDD (controller, `afi-safi mup segment direct
  network-instance core`, drives `pfcp-inject` with a `core` Network
  Instance → ST2 with endpoint + TEID + Direct segment id, received by the
  peer); `@bgp_mup_segment_dsd` extended to assert the DSD carries
  `RT:65501:10 1:2`. Run live via `make -C bdd bgp_mup_st2` /
  `bgp_mup_segment_dsd`.

**Still open in P6 (unchanged):** the *receive* side (ST2 → Direct-segment
resolution → FIB), ISD (`segment interwork`) origination, and the GTP
behaviours.

#### P6 slice 3 — receive-side ST2 → Direct-segment resolution — **DONE**

The interwork (SRGW) node — any VRF with `afi-safi mup segment
interwork` — now resolves each received Type-2 ST route to the Direct
segment it forwards into, the control-plane half of
draft-mpmz-bess-mup-safi §3.3.12:

- **Resolution.** `show bgp mup` indexes the selected DSD routes by their
  BGP MUP Extended Community (Direct-segment id, type 0x0c / sub-type
  0x00) and, for each received ST2 carrying the same id, prints the
  End.DT46 segment and the DSD it resolves to:
  `resolved 1:2 -> End.DT46 <sid> (via [DSD][rd][addr])`. Gated on the
  node being an interwork node (a `segment interwork` VRF) — a
  `segment direct` PE or a controller shows nothing. Pure control plane,
  computed over the global MUP Loc-RIB (`render_mup_table` in
  `zebra-rs/src/bgp/show.rs`); no new RIB state.
- **FIB still deferred.** Actually forwarding the uplink — GTP-U decap
  (`H.M.GTP4.D`) then SRv6 H.Encaps toward the resolved End.DT46 SID —
  needs VPP / eBPF (mainline Linux `seg6local` has no `End.M.GTP*` /
  `H.M.GTP4.D`), so this slice binds the segment but does not install the
  decap.
- **Test.** `@bgp_mup_interwork` BDD: z1 (combined UPF + controller)
  originates a DSD (End.DT46 + id 1:2) and an ST2 (id 1:2) from a PFCP
  session; z2 (`segment interwork`) resolves the ST2 to z1's End.DT46
  Direct segment. Plus a `render_mup_table` unit test. Run live via
  `make -C bdd bgp_mup_interwork`.

**Still open in P6 (unchanged):** the receive-side *FIB* write (above),
ISD (`segment interwork`) route origination, and the GTP behaviours.

#### Remaining

**What:** Install the FIB state that actually forwards MUP traffic. With
the draft-default model (see *Draft-default forwarding* above), the PE
receiving an ST route resolves its forwarding SID from the matching
ISD / DSD route rather than from a SID carried on the ST route — so P6
gains an *ISD/DSD-route → segment-SID resolution* step ahead of the FIB
write. Per the chosen "install what the kernel supports" scope: program
`End.DT4/6` + the route-level SIDs we already do for L3VPN/SRv6, and flag
the GTP behaviours (`End.M.GTP4.E` / `End.M.GTP6.E` / `GTP4.E` /
`GTP6.E`) as needing VPP or eBPF — mainline Linux `seg6local` has no
`End.M.GTP*` actions. See the kernel-support note in
[`bgp-prefix-sid-rfc9252.md`](bgp-prefix-sid-rfc9252.md) and
[`srv6-l3vpn` forwarding notes](../../zebra-rs-srv6-l3vpn-forwarding-bugs.md).

**Where:** the FIB install path + `seg6local` programming.

**Size:** large.

## Quick-pick recommendations

By value-per-line, if picking one up independently of P5/P6:

1. **#7 (`show bgp mup` JSON)** — cheap, mechanical, zero risk.
2. **#11 (eBGP v6 next-hop-self)** — small RFC-correctness fix.
3. **#4 (RFC 7606 attr-level treat-as-withdraw for MUP)** — closes a
   small correctness/robustness gap on malformed UPDATEs.
4. **#1 + #9 (per-AFI MUP inbound + outbound policy)** — do together;
   first thing a real deployment with filtering will need.

Larger items (#3 VRF import, #8 update-groups, #10 AddPath TX, #13
strict route-key) should each gate on a concrete consumer. With **P5
built**, the next real milestone is **P6 (the SRv6-mobile dataplane)**;
most of the larger items above now have a concrete consumer in the
controller and can be picked up as deployments demand them.

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
