# BGP path selection and update generation — adversarial review

Scope: best-path selection, update generation and every path that re-runs
them, across update-groups, AddPath on/off, and every address family
(IPv4/IPv6 unicast, VPNv4/VPNv6, labeled-unicast v4/v6, EVPN, plus
MUP/Flowspec/SR-Policy/RTC where they share the machinery). Reviewed
against `main` at `2f1e9a09` (2026-09-07). Line numbers are as of that
commit.

Method: one lead read the selection ladder and every egress builder, then
five independent read-only reviewers each took one dimension (update-group
sharing, the selection ladder and inbound attrs, AddPath, per-family egress
consistency, state transitions). Every finding the lead could reach from a
unit test was pinned with a probe test; those are marked **probe** below
and the probe module is kept out of the tree (see "Probes"). Everything
already recorded in `bgp-code-review-findings.md` was excluded unless it
turned out worse than recorded.

Severity: P1 = silent route loss, blackhole, wrong forwarding, or livelock
in a realistic configuration. P2 = wrong behavior or non-conformance with
operational impact. P3 = edge, latent, or churn. Confidence: CONFIRMED =
every branch traced or a probe fails on `main`; PLAUSIBLE = mechanism read
but not exercised.

## Summary

Nine P1, sixteen P2 and seven P3 findings, plus a list of one-line items
below the cap. Four root causes account for most of them:

1. **Per-peer egress inputs outside the update-group signature.** The
   memoized canonical-member transform is replayed to group-mates whose
   own knob or policy differs (#3, #4, #13, #21). The invariant stated
   near `route.rs:4975` is not enforced by anything structural, and the
   only regroup points are the Established edge and the egress-script
   rebind.
2. **Inbound attributes from eBGP taken at face value.** LOCAL_PREF,
   ORIGINATOR_ID and CLUSTER_LIST are never discarded on eBGP ingest, so an
   external neighbor decides our best path and gets relayed AS-wide (#1,
   #11).
3. **Reflection, AddPath and stale handling modeled on "best only" or
   "VPNv4 only".** No per-path "learned from a client" state (#2); EVPN
   AddPath and several sync/soft paths still iterate `selected` (#7, #16,
   #18, #20); the plain fan-out takes `selected.last()` although the
   winner is first (#14); the stale sweep walks VPNv4 only (#9).
4. **v4/v6 twins that drifted.** The v6 withdraw lacks the v4 guard (#5),
   the v6 AddPath loop lacks the v4 out-policy call (#16), VPNv6 lacks the
   VPNv4 transit label (#8), and the `(Ip6, Unicast)` knobs govern VPNv6
   rows (#13).

Related: a parallel session left an independent review of the same
commit in `docs/reviews/bgp-path-update-2026-09-07/` (nine findings,
seven probes as an unapplied patch). Its findings 1, 2, 3, 4, 5, 6 and 8
are this document's #16, #15, #17, #7, #14, #3 and #32; its finding 9 is
the SR-Policy reflector item already in `bgp-code-review-findings.md`; its
finding 7 (gate-on group engine does not retract a route from a member
that becomes the new source) is not covered here and is listed below the
cap. The two reviews agree on every overlapping item.

## Ranked findings

### 1. P1 CONFIRMED (probe) — LOCAL_PREF received from an eBGP peer decides our best path and is relayed AS-wide

- `crates/bgp-packet/src/attrs/attr.rs:501` stores LOCAL_PREF for every
  session; `route.rs:4171` `inbound_attr_checks` (and the seven inlined
  copies for v6/LU/EVPN/MUP/FS/SR/LS) never discard it; `route.rs:2369`
  `is_better` reads `effective_local_pref` regardless of `rib.typ`; every
  iBGP builder only defaults when absent (`12891`, `13100`, `6147`,
  `9972`, `11119`, `13450`, `13536`). The only `local_pref = None` in the
  tree is the eBGP egress strip (`12751`).
- Scenario: an eBGP customer or peer sends a prefix with LOCAL_PREF
  4294967295. It beats every internal path at step 4, is installed, and is
  re-advertised to all iBGP peers carrying that LOCAL_PREF, so the whole AS
  prefers the customer exit. RFC 4271 §5.1.5 says the attribute MUST be
  ignored on eBGP; RFC 7606 §7.6 says discard.
- Probe `probe_b1_ebgp_local_pref_steers_selection`: an eBGP row with
  AS_PATH `65002 65009` and LOCAL_PREF 500 beats an eBGP row with
  AS_PATH `65001`; winner reason `LocalPref`.
- Fix direction: discard LOCAL_PREF (and see #11) in `inbound_attr_checks`
  when the peer is eBGP, returning a stripped attr the way `otc_stamped`
  does, so all eight ingest copies inherit it.
- BDD gates: `bgp_ebgp_local_pref_ignore` (IPv4, traditional NLRI) and
  `bgp_ebgp_local_pref_ignore_v6` (IPv6 transport, MP_REACH_NLRI AFI 2),
  both driven by the scripted eBGP speaker
  `tests/scripts/bgp_ebgp_local_pref_send.py`. Each fails on `main` at
  exactly the three LOCAL_PREF assertions (row carries 500, FIB follows
  the eBGP path, iBGP peer receives 500) and passes its four control
  scenarios, so the fix must cover `route_ipv4_update` and
  `route_ipv6_update` ingest alike.
- FIXED (branch `bgp-ebgp-local-pref-ignore`) at the parser, the way FRR
  does it: `ParseOption` gained `peer_type: BgpPeerType` (`Ibgp` by
  default, so callers that do not say keep every attribute),
  `peer_start_reader` stamps it from the peer's configured type next to
  the AS4 stamp (`opt.peer_type = peer.peer_type.into()`), and
  `parse_bgp_update_attribute` skips a LOCAL_PREF from an external session
  (`is_ebgp`) before the value parse, so a malformed one is discarded too
  instead of resetting the session (RFC 7606 §7.6). A parse with no
  option keeps the attribute (default session type `Ibgp`); every
  production parse passes the session's option. Every family and the
  Adj-RIB-In see the UPDATE as if the attribute had never been sent;
  inbound policy still runs after parsing, so `set local-pref` on an eBGP
  session keeps working.
  Both BDD gates pass 7/7 with the fix. Not covered: ORIGINATOR_ID /
  CLUSTER_LIST from eBGP (#11, same parser site), and a malformed
  LOCAL_PREF from an *internal* peer still resets the session where
  RFC 7606 §7.6 asks for treat-as-withdraw (`attr_malformation_is_withdraw`
  does not list `LocalPref`).

### 2. P1 CONFIRMED (probe) — a route learned from a reflector client is never reflected to non-client iBGP peers

- `BgpRib` (`route.rs:1811`) has no "learned from a client" bit. Every
  builder gates iBGP-to-iBGP on the destination alone:
  `route.rs:12777` (v4/VPNv4), `12983` (v6/VPNv6), `13412`/`13503`
  (LU), `5957` (EVPN), `9937` (MUP), `11106` (Flowspec),
  `sr_policy.rs:906`. Nothing in `vrf/` compensates.
- RFC 4456 §6: from a client, reflect to all non-clients and all other
  clients. Scenario: the standard hierarchical design (RR1 and RR2 peer as
  non-clients, each with clients). Client routes reach RR1 and never cross
  to RR2, so RR2's clients never learn them. Every RR BDD config
  (`bgp_basic_rr`, `bgp_rr_ebgp_strip`, `bgp_ebgp_strip_v6`,
  `bgp_evpn_rr_withdraw`, `bgp_lu_rr_transit_label`,
  `bgp_vpnv4_rr_transit_label`, `bgp_evpn_srv6_rr`) makes every iBGP
  neighbor a client; `bgp_vrf_neighbor_rr_client` covers non-client
  sources only.
- Probe `probe_f15_client_route_reflected_to_non_client`: client to other
  client delivered, client to non-client `adj_out` empty.
- Fix direction: carry `from_client: bool` on `BgpRib` (stamped in
  `inbound_attr_checks`) and reflect when `ctx.reflector_client ||
  rib.from_client`. This is a source-path input, not a destination knob,
  so it is signature-neutral.

### 3. P1 CONFIRMED (probe) — `afi-safi ipv4|ipv6 next-hop-self` / `next-hop-unchanged` are missing from `UpdateGroupSig`

- Commit `0fcce89d` added `unicast_next_hop_self` /
  `unicast_next_hop_unchanged` to `SyncCtx` (`peer.rs:1752-1757`) and made
  `route_update_ipv4` (`route.rs:12813-12825`) and `route_update_ipv6`
  (`13026-13030`, reading `peer.next_hop_self(Ip6, Unicast)`) honor them,
  but `signature_of` (`update_group.rs:396`) still stamps only the VPNv4
  pair. `route_advertise_batch` (`route.rs:5893`) memoizes the first
  member's outcome per group and `V4Batch::advertise` records it in every
  member's Adj-RIB-Out.
- Scenario: two iBGP peers with `update-source lo` (same `local_addr`, so
  one group), one with `next-hop-self`. Whichever has the lower ident is
  canonical. If it is the plain one, the `next-hop-self` peer keeps a
  next-hop it may not resolve; if it is the `next-hop-self` one, the plain
  peer's next-hop is rewritten to this router, which pulls traffic through
  a reflector that may not be in the forwarding path. Same for an IXP
  segment where several eBGP peers share one interface address and only
  some are `next-hop-unchanged`. The BDD `bgp_vrf_neighbor_next_hop`
  passes because each CE sits on its own subnet, so `local_addr` differs
  and the peers never share a group.
- Probes `probe_f1_*` (v4, both orders) and `probe_f1c_*` (v6): both
  members record the same next-hop; in the swapped order the plain member
  gets `10.0.0.9` (self).
- Fix direction: add `unicast_next_hop_self` / `unicast_next_hop_unchanged`
  to the signature for `(Ip, Unicast)` and `(Ip6, Unicast)` (family-gated
  like `vpnv4_*`), bump `SIGNATURE_VERSION`, extend
  `egress_knobs_shard_only_their_family`.

### 4. P1 CONFIRMED (probe) — binding an out-policy or prefix-set on a live peer never regroups, so the memo applies one peer's policy to its group-mates

- `config.rs:733-749` (`config_afi_safi_policy_out`) → `683-708`
  (`apply_peer_afi_policy_ref`), `757+` (prefix-set out),
  `neighbor_group.rs:1719-1740` (group sweep) rewrite the slot name and
  register with the policy actor; the resolve path (`inst.rs:6246-6351`)
  calls `rebuild_out_policy` and a per-peer soft-out. `signature_of` is
  recomputed only at `peer.rs:2231` (Established edge) and
  `config.rs:190-207` (egress-script rebind); `config.rs:393`,
  `inst.rs:2736`, `vrf/inst.rs:3417`, `interface_neighbor.rs:339` only
  detach. `policy_out_name` is a signature field, so the peer now sits in
  a group whose `sig` no longer matches it.
- Scenario: group {A, B, C}, no policies; operator binds `policy out
  DENY` on A. A's own soft-out withdraws correctly. From the next best-path
  change on, A is canonical: its `Withdraw` outcome is memoized and B and
  C get explicit withdraws for every route that changes. With a `set
  med`/`set community` policy they get A's rewritten attributes. If A has
  the higher ident the reverse happens and A bypasses its own policy.
  Aggravator: A's soft-out calls `cache_remove_ipv4(group, prefix, 0)`
  (`route.rs:6995`) for every denied prefix, deleting B's and C's pending
  advertises inside the MRAI window. Same shape at gate-on
  (`soft_out_v4_to_group`, `route.rs:5406-5451`) and for VPNv4/VPNv6/v6
  via `route_apply_policy_out_at`/`_v6`.
- Probe `probe_a2_out_policy_bound_live_leaks_through_group_memo`: after
  binding a deny list on A, `signature_of(A) != signature_of(B)` but both
  keep the same group id, and B's `adj_out` stays empty for a route it has
  no policy against.
- Fix direction: any config handler that mutates a signature-bearing field
  on an Established peer must detach/attach (a `resign_update_groups(peer)`
  helper called from the policy/prefix-set binding, the neighbor-group
  sweep, and every knob in #21). The already-recorded `config.rs:961`
  finding is the same class; this one is the most common runtime
  operation.

### 5. P1 CONFIRMED (probe) — `V6Batch::withdraw` clobbers the group's pending advertise when the source member is withdrawn

- `route.rs:5787-5806` (v6) has no `per_peer_suppress` guard, unlike
  `V4Batch::withdraw` (`5585-5598`). `route_advertise_batch` yields
  `Withdraw` for the source member (`5888`) and for non-LLGR members
  (`5889`); if that member's `adj_out.v6` holds the prefix (it received it
  under the previous best), the v6 withdraw calls
  `cache_remove_ipv6(group, prefix, 0)` (`update_group.rs:1250`), which
  pops the NLRI a lower-ident sibling just queued via `send_ipv6`.
- Scenario: RR with clients M (lower ident) and S in one v6 group; P is
  best via an external peer T and both hold it. S advertises a better P.
  M's Adj-RIB-Out records P via S, the group cache entry is deleted before
  the flush, the wire still says P via T. Dedup suppresses a resend until
  P's best changes again; once T's path is gone M forwards into a hole.
  LLGR-mixed groups hit the same branch.
- Probe `probe_a1_v6_source_member_withdraw_clobbers_sibling_pending_advertise`
  fails (pending entry gone, M's `adj_out` says next-hop S); the v4
  control `probe_a1_control_v4_*` passes.
- Fix direction: mirror the v4 `per_peer_suppress` computation in
  `V6Batch::withdraw`.

### 6. P1 CONFIRMED (probe for the re-send; loop by mechanism) — labeled-unicast AddPath fan-out has no Adj-RIB-Out dedup, so two mutual AddPath LU peers re-send each other forever

- `route.rs:13905-13925` (AddPath loop of `route_advertise_labeled`)
  calls `A::adj_out_record(peer, prefix, cand, true)` and discards the
  previous row, then `peer.send_update` unconditionally for every
  candidate on every event; the plain branch (`13876-13882`) was fixed
  with `same_advertised` after the 20 kHz loop of 2026-09-04. LU is
  immediate per-peer send with no MRAI cache, and
  `route_labelv4/6_update` (`7886`, `8008`) re-advertises on every
  ingest, including an identical implicit replace.
- Scenario: R1 and R2 with `afi-safi label-v4 add-path send-receive`
  toward each other, each with an upstream (or both originating P). R1
  sends its candidate, R2 ingests and re-sends its own candidate back
  (split-horizon only skips the path R1 sourced), R1 ingests and re-sends,
  bounded only by RTT.
- Probe `probe_c1_lu_addpath_resends_unchanged_candidate`: the same
  `selected` fanned twice to one AddPath LU peer produces two UPDATEs.
- Fix direction: in the AddPath branch, skip `send_update` when
  `adj_out_record` returns a previous row for the same `local_id` and
  `same_advertised(prev, cand)`.

### 7. P1 CONFIRMED — EVPN AddPath members receive the best path only, and the superseded path-id is never withdrawn on a flip

- `route.rs:6704-6728` iterates `selected` for AddPath members;
  `LocalRibEvpnTable::select_best_path` (`2660-2706`) returns exactly
  one; `route_sync_evpn` (`15419`) dumps `table.selected`. On a flip
  A(id 1) → B(id 2), `route_evpn_withdraw` (`9575-9586`) re-advertises the
  survivor, `route_update_evpn` stamps `local_id` 2, nothing withdraws
  id 1, and `adj_out.add_evpn` (`6688`, keyed by `local_id`) now holds
  both rows. EVPN AddPath send is negotiable (`cap.rs:105-115`,
  `peer.rs:3385`, `zebra-bgp-afi-knobs.yang:66`).
- Scenario: RR with `afi-safi evpn add-path send` toward leaf C; MAC/IP M
  from VTEP A (best) and VTEP B. A's session dies. C receives reach(M,
  id 2, nh B) only and keeps id 1 toward the dead VTEP until M is
  withdrawn everywhere. Same class as the v6/LU AddPath bug fixed on
  2026-06-14, one family later.
- Fix direction: give the EVPN AddPath loop the v6/LU shape (read the full
  `cands` from `local_rib.evpn[rd].cands`, diff against `adj_out` ids,
  withdraw the ids that dropped out).

### 8. P1 CONFIRMED — VPNv6 next-hop-self / eBGP re-advertisement sends the received label behind a self next-hop; no VPNv6 transit label exists

- `route.rs:5737` (`V6Batch::advertise`, `b.label.unwrap_or_default()`),
  `5831` (AddPath), `15275` (`route_sync_vpnv6`) put the received label
  on the wire while `route_update_ipv6` (`13031-13050`) rewrites the
  next-hop to self for eBGP and `next-hop-self`. The VPNv4 twin uses
  `vpnv4_service_label` (`12631`, `rib.local_label`) minted by
  `label_vpn_v4` under `vpn_v4_transit`; `inst.rs:4826-4846`
  (`transit_needed` / `reconcile_transit_labels`) arms VPNv4, LU4, LU6
  only. `Label::default()` is label 0.
- The book (`ch-02-21-bgp-interas-option-b.md:4`, `:158`) documents
  "MP-eBGP VPNv4/VPNv6" Option B and says the label block is requested
  for `vpnv6` too. Scenario: asbr2 learns 2001:db8:1::/64 from asbr1 with
  pe1's label, re-advertises to pe2 with nh = self and pe1's label; pe2
  pushes a label asbr2 holds no ILM for (drop), or one that collides with
  a local dynamic-block label (delivered into the wrong VRF).
- Fix direction: either add the VPNv6 transit flag + minting + swap ILM
  (`label_vpn_v6`, `vpn_v6_transit`), or reject `vpnv6` on eBGP /
  `next-hop-self` sessions and fix the book.

### 9. P1 CONFIRMED — LLGR / PIC stale rows for VPNv6 and EVPN never expire, and any family's EoR flushes the VPNv4 stale set

- `route.rs:12581-12620` `stale_route_withdraw` walks only
  `adj_in.v4vpn` and is the crate's sole stale sweeper; `12574-12579`
  `eor_stale_expire` removes the per-AFI timer for the given family and
  then calls that AFI-blind sweep; `peer.rs:2085-2087`, `2107-2109`
  (`StaleExpire(_afi_safi)`) do the same. `route_clean` retains VPNv6
  rows stale (`11975-12100`) and EVPN rows stale (`12130-12220`) and arms
  `(Ip6, MplsVpn)` / `(L2vpn, Evpn)` timers. Every EoR variant
  (`11590-11695`) reaches `eor_stale_expire`. `evpn_advertise_one`
  (`6670-6681`) returns `false` on the LLGR gate and
  `route_advertise_evpn_to_peers` ignores it, so no withdraw reaches
  non-LLGR EVPN peers at the stale flip either.
- Scenario A: a PE with LLGR or `pic-retention` for vpnv6/evpn loses its
  session permanently while the IGP still resolves its loopback. Its VPNv6
  rows and EVPN Type-2/Type-5 rows stay in the Loc-RIB, VRF FIB and kernel
  FDB and stay advertised with LLGR_STALE for the daemon's life; EVPN has
  no NHT gate, so MAC-to-dead-VTEP forwarding never recovers.
  Scenario B: graceful restart of a VPNv4 PE. Its first EoR (typically
  ipv4-unicast, sent before VPNv4 is fully re-advertised) sweeps every
  not-yet-refreshed VPNv4 stale row, the transient L3VPN blackhole GR
  exists to prevent.
- Probe sketch: twin of `vpnv4_eor_flushes_stale_routes_and_cancels_timer`
  (`route.rs:26015`) with `add_v6vpn` and `MpUnreachAttr::Vpnv6Eor`,
  assert the v6vpn stale count is 0; second variant with a VPNv4 stale row
  and `Ipv4Eor`, assert the count is still 1.
- Fix direction: make the sweep per-family (`stale_route_withdraw(peer,
  afi_safi)`) covering v4vpn, v6vpn, evpn (and any other family
  `route_clean` retains), and pass the EoR's family through.

### 10. P2 CONFIRMED (probe) — MED comparison is order-dependent, and an unchanged re-advertisement rotates the winner

- `route.rs:2182-2190` scans candidates linearly with pairwise
  `is_better`; MED is compared only within one neighboring AS
  (`2405-2412`), which is non-transitive. `LocalRibTable::update`
  (`2108-2148`) `extract_if`s the replaced row and pushes the new one at
  the tail, and the shard ingest (`shard/dispatch.rs:473`) has no
  unchanged-attr short-circuit, so every re-advertisement reorders the
  candidates.
- Probe `probe_f3_med_winner_depends_on_candidate_order`: with
  A{AS 65001, MED 10}, B{AS 65002}, C{AS 65001, MED 5}, order [A,B,C]
  picks C and [A,C,B] picks B; feeding the three unchanged routes again in
  turn cycles the winner 2, 1, 3, 2, 1, 3. Each flip is a new UPDATE to
  every peer and a FIB change with nothing having changed.
- Fix direction: deterministic MED (group candidates by neighboring AS,
  pick the per-AS MED winner, then compare winners), or at least keep the
  candidate order stable on replace.

### 11. P2 CONFIRMED (probe) — ORIGINATOR_ID / CLUSTER_LIST from an eBGP peer decide ties and are relayed into the AS

- `route.rs:2555` `bgp_identifier` prefers `originator_id` with no `typ`
  gate; `4185-4193` only drops when the value is our own router-id; the
  egress stamping (`12897-12915`) is gated on `rib.typ == IBGP`, so an
  eBGP-learned route carries the injected attributes to every iBGP peer.
  RFC 7606 §7.11/§7.12 say discard on eBGP.
- Scenarios: ORIGINATOR_ID 0.0.0.0 wins every (f) tie (probe
  `probe_b4_ebgp_originator_id_wins_tie`); ORIGINATOR_ID = the router-id
  of our internal router R, or CLUSTER_LIST containing it, makes R drop
  the prefix at its own inbound check, a targeted suppression from
  outside. PLAUSIBLE adjunct: an OPEN with BGP Identifier 0.0.0.0 is
  accepted (`peer.rs:2478-2483`, `2549`; RFC 6286 §2.2 says NOTIFY) and
  then wins all (f) ties.
- Fix direction: same site as #1.

### 12. P2 CONFIRMED (probe) — `enforce-first-as` with `local-as` (without `no-prepend`) drops every route from the neighbor

- `route.rs:11328-11336` (`route_from_peer`) prepends the substitute AS
  before the per-family dispatch; `4182` then runs
  `aspath_enforce_first_as_violation` (`131`) against `peer.remote_as`
  and sees `[substitute, remote_as, ...]`. `aspath_own_as_loop` budgets
  the prepend; the first-AS check does not. FRR checks first-AS before the
  prepend.
- Probe `probe_b2_enforce_first_as_with_local_as_prepend`: path after
  ingress prepend `64999 65001 65009`, violation reported. Adj-RIB-In
  fills, Loc-RIB stays empty, nothing logs.
- Fix direction: run the first-AS check on the pre-prepend path (or accept
  `substitute` as the first AS when `change_local_as()` is active).

### 13. P2 CONFIRMED — `afi-safi ipv6 next-hop-self|next-hop-unchanged` silently govern VPNv6 rows

- `route.rs:13026` and `13030` evaluate the `(Ip6, Unicast)` knobs for
  every row, including `Some(VpnNexthop::V6)` rows (the VPNv6 shape is only
  chosen at `13045`). VPNv4 reads `(Ip, MplsVpn)`. The recorded finding
  says the vpnv6 knob is ignored; the actual behavior is that the wrong
  family's knob applies.
- Scenario: RR with `afi-safi ipv6 next-hop-self` (routine for
  eBGP-learned v6 unicast) that also carries `vpnv6` to the same iBGP
  neighbor: every reflected VPNv6 row is rewritten to nh = self with the
  originating PE's label (#8), blackholing all VPNv6 through that neighbor.
  `next-hop-unchanged` on an eBGP peer likewise keeps foreign next-hops on
  VPNv6. Neither knob is in the VPNv6 signature, so it is also a memo leak
  between group-mates.
- Fix direction: gate the two reads on `rib.nexthop.is_none()` and read
  `(Ip6, MplsVpn)` for VPN rows; add both to the VPNv6 signature.

### 14. P2 CONFIRMED (probe) — with `maximum-paths > 1` the plain fan-out advertises a multipath member, not the winner

- `select_best_path` pushes the winner first (`route.rs:2211`) and the
  ECMP members after it (`2266`); every plain fan-out takes
  `selected.last()` as "best": `route_advertise_batch` (`5870`), the
  parallel memo (`4434`), `fan_advertise_to_groups` (`5247`),
  `fan_advertise_to_pets` (`5214`), LU (`13794`), EVPN (`6711`), MUP
  (`10072`), Flowspec (`11067`). FIB and VRF export use `.first()`
  (`1002`, `4604`, `7584`). `multipath_resync` (`inst.rs:6563-6612`)
  re-selects without advertising, so a runtime `maximum-paths` change can
  leave a dropped leg on the wire.
- Probe `probe_c7_plain_fanout_advertises_multipath_member_not_winner`:
  `selected = [(1, best), (2, multipath)]`, the peer's Adj-RIB-Out row is
  ident 2 with `best_path = false`. A member-set change without a winner
  change therefore re-advertises a different path, and `show bgp` and the
  wire disagree. `bgp_multipath.feature` asserts the FIB only.
- Fix direction: use `selected.first()` (the `.last()` predates the
  multipath extension, when `selected` was a change history).

### 15. P2 CONFIRMED (probe), worse than recorded — advertise-cache forward/reverse desync leaves a phantom route that is never withdrawn

- `update_group.rs:694-712` (`send_ipv4`) / `1228-1244` (`send_ipv6`)
  still insert the NLRI into the new attr bucket without evicting the old
  one; `721-731` (`cache_remove_ipv4`) purges only the reverse-mapped
  bucket. New consequence: after A1 → A2 → withdraw inside one MRAI, the
  flush re-announces P under A1 while `adj_out` no longer holds P, and
  every later Loc-RIB withdraw is skipped by the `adj_out.contains_key`
  gate (`route.rs:5599`, `5806`); the deferred-withdraw replay has the
  same gate. The phantom lives until P is re-advertised.
- Probe `probe_a4_pending_cache_keeps_nlri_in_superseded_bucket`: after
  the withdraw the reverse map is empty but one bucket still holds the
  NLRI.
- Fix direction: in `send_*`, evict the NLRI from the bucket the reverse
  map points at when the attr differs.

### 16. P2 CONFIRMED — the IPv6-unicast AddPath event path bypasses outbound policy

- `route.rs:13253-13290`: `route_update_ipv6` → intern → `send_ipv6`,
  with no `route_apply_policy_out_v6`. Plain members go through
  `compute_advertise_outcome_v6` (`5666`), the session-up dump applies
  it (`15108`), and `V6Batch::advertise_addpath` (`5804`, which does
  apply it) is reachable only for VPNv6 (`13352`). AddPath-send peers are
  not in `established_plain_idents`, so this loop is their only event
  path.
- Scenario: `afi-safi ipv6 add-path send` plus a `policy out` denying a
  prefix: filtered at session-up, leaked on the first churn; `set
  community`/`set med` absent on every event-driven AddPath UPDATE.
- Fix direction: call `route_apply_policy_out_v6` in the loop, as the LU
  generic (`13878`) does.

### 17. P2 CONFIRMED — v4-unicast / VPNv4 / VPNv6 AddPath: a replaced candidate that becomes egress-filtered (or LLGR-stale) is never withdrawn

- `route.rs:4716-4726` (`apply_ipv4_advertise_job`): `Some(added)` →
  advertise only; `replaced` is withdrawn only when `added.is_none()`.
  `V4Batch::advertise_addpath` (`5606-5636`) and `V6Batch::advertise_addpath`
  (`5804-5822`) `return` on a `None` from the builder (NO_EXPORT /
  NO_ADVERTISE, `as_sets_withdraw`, OTC ER2, `vrf_transit_only`), on an
  out-policy deny, and on an RTC mismatch; `route_advertise_batch_addpath`
  (`4877-4890`) `continue`s on LLGR with no withdraw and no `adj_out`
  touch. The stale re-insert on peer-down arrives as `added: Some` with
  the same `local_id` (`LocalRibTable::update` reuses it), so nothing else
  distinguishes it. The gate-on group engine does it right
  (`group_egress.rs:287-289`); v6-unicast and LU diff loops do it right.
- Scenarios: AddPath peer B holds (P, id 1) from A; A re-advertises P with
  NO_EXPORT (or B's out-policy now denies it), B keeps id 1 with the old
  attributes forever. RR with non-LLGR AddPath VPNv4 clients and an
  LLGR-negotiated PE session that goes down: plain clients get the
  withdraw immediately, AddPath clients keep the pre-stale path-id and
  forward to the dead PE until the stale sweep (hours), and for VPNv6
  never (#9).
- Fix direction: when the AddPath advertise is filtered or LLGR-blocked
  and `adj_out` holds (prefix, id), send the exact-id withdraw.

### 18. P2 CONFIRMED — v4/VPNv4 soft-out toward an AddPath peer emits path-id-0 withdraws and never reconciles non-best ids

- `route_soft_out_peer_table` (`route.rs:6858-6870`) reads `.1`
  (best-only); its withdraw loop (`6980-7008`) uses id 0:
  `withdraw_ipv4_deferrable(.., prefix, 0)`, `cache_remove_ipv4(.., 0)`,
  `adj_out.remove(rd, prefix, 0)` (wildcard). `Ipv4Nlri::nlri_emit`
  (`crates/bgp-packet/src/attrs/nlri_ipv4.rs:24-28`) and the VPNv4
  emitter write the path-id only when `id != 0`, so on a session where the
  peer negotiated AddPath receive the withdraw NLRI has no path-id and the
  peer parses the prefix length as the first path-id octet. EVPN soft-out
  (`7015-7100`) diffs at (prefix, id) correctly.
- Scenario: `clear bgp <B> soft out` or an out-policy edit on an AddPath
  peer that newly denies P: a malformed withdraw (UPDATE error or bogus
  withdraw at the peer); the prefix's other path-ids at B are never
  re-evaluated; the wildcard `adj_out.remove` erases every local row, so
  later exact-id withdraws find nothing to prune.
- Fix direction: give the v4/VPNv4 soft-out the EVPN (prefix, id) diff
  and never send id 0 to an AddPath-negotiated peer.

### 19. P2 CONFIRMED — RTC membership learned mid-session never triggers an advertisement

- `route.rs:8122` / `8133` (`route_ipv{4,6}_rtc_update`) only insert
  into `peer.rtcv4/6`; `route_rtcv4_sync` (`8143`) runs only on an
  `Rtcv4Eor` while `peer.eor` still holds the key from session-up
  (`15590`) and then clears it; `Rtcv6Eor` (`11599`) is a no-op. Every
  event path "skips without withdrawing" on an RTC mismatch (`5537`,
  `5630`, `5721`, `5827`, `6926`). The withdraw side is already recorded.
- Scenario: PE adds a VRF importing a new RT after the session is up; the
  RR stores the RTC NLRI and never sends the existing VPN routes carrying
  that RT until reset or per-prefix churn. EVPN and MUP apply no RTC at all
  (`6670`, `10031`).
- Fix direction: on an exact RTC add, run a targeted re-sync of the VPN
  tables filtered to the new RT (or the full `route_sync_vpnv4/6`).

### 20. P2 CONFIRMED — LU session-up sync dumps the most recently updated candidate, not the winner

- `route.rs:15484-15490` and `15535-15541` (`route_sync_labelv4/v6`,
  plain branch): `ribs.last()` over `shard.v4lu.0` / `v6lu.0`, i.e. the
  candidate vec, whose tail is the last replaced row (`2136`);
  `select_best_path` only flags. `route_sync_ipv4` reads `.1` correctly.
- Scenario: ASBR holds loopback L from PE1 (better, older) and PE2
  (worse, or unreachable, refreshed last). A new plain LU peer receives
  PE2's path and label until the next event for L, when `same_advertised`
  differs and corrects it.
- Fix direction: read `shard.v4lu.1` / `v6lu.1` in the plain branch.

### 21. P2 CONFIRMED — more signature-bearing knobs change on a live Established peer without detach/attach

- Beyond the recorded as-override / remove-private-as / rr-client:
  `config_remote_as` (`config.rs:561-590`, rewrites `remote_as` and flips
  `peer_type`; `peer.start()` is a no-op on an active peer), vpnv4
  `next-hop-self` / `next-hop-unchanged` (`config.rs:3644-3663` →
  `afi_knob.rs:131-140`), ipv6 `encapsulation-type` (`config.rs:3627-3632`),
  `local-as ... no-prepend|replace-as` (`config.rs:1355-1410`, "no session
  bounce" by design), `attach-unknown-attribute` (`config.rs:1266-1278`),
  `advertisement-interval` (`timer.rs:441-452`; also never honoured by the
  VPNv4/VPNv6/EVPN per-peer timers, `timer.rs:212-227`). `bgp router-id`
  change (`inst.rs:2147-2262`) leaves reflected ORIGINATOR_ID /
  CLUSTER_LIST and the gate-on `SyncCtx.router_id` stale. By contrast
  `otc-local-role`, `route-server-client`, `local-as` number,
  `update-source` and `ttl-security` bounce the session.
- Consequence: the peer stays in a group whose `sig` no longer describes
  it, so a runtime toggle re-opens the recorded findings #7/#8 (SRv6 SID
  leaked to a plain CE, Option-B next-hop blackhole), and an iBGP/eBGP
  flip shares prepend/strip/next-hop rules with the wrong group.
- Fix direction: same helper as #4.

### 22. P2 CONFIRMED (env-gated) — gate-on group engine skips peer slot 0 on every NHT-, FIB-release- and import-driven withdraw

- Sources that pass a literal `0` as the split-horizon source:
  `shard/dispatch.rs:581-597` (`reeval_nexthop_v4`, `ident: 0`) →
  `route.rs:4777` → `4695` `fan_advertise_to_groups` → `5278`
  `Withdraw { source_ident: 0 }`; N=1 `inst.rs:5813-5821`;
  `fib_pending_release_v4` (`route.rs:5202`); VRF import / import-withdraw
  toward CE peers (`vrf/inst.rs:2439-2446`, `2547-2554`).
  `group_egress.rs:345-354` `fan` skips `ident == source_ident`.
  `ORIGINATED_PEER` is `usize::MAX` (`route.rs:27`); `peer_map.rs:67-71`
  hands ident 0 to the first configured neighbor. Only under
  `ZEBRA_BGP_EGRESS_GROUP_TASK=1`; the default `route_advertise_batch`
  ignores `_source_peer`.
- Scenario: next-hop N becomes unreachable; the prefix is withdrawn
  locally and from every member except slot 0, which keeps forwarding to
  us. An L3VPN PE with one CE in the VRF (ident 0) drops every remote-PE
  withdraw at the CE.
- Fix direction: use `ORIGINATED_PEER` as the no-source sentinel at the
  call sites.

### 23. P2 CONFIRMED — NHT flips never reach AddPath peers, and next-hop-unreachable candidates are advertised to them

- N=1: `inst.rs:5813-5821` / `5858-5866` / `5906-5912` call only the
  best-path fans (`route_advertise_to_peers` / `_vpnv6`), never
  `route_advertise_to_addpath` / `route_withdraw_from_addpath`. N>1:
  `shard/dispatch.rs:581-600` (`reeval_nexthop_v4`) yields `added: None,
  replaced: []`, so `apply_ipv4_advertise_job` (`4717-4725`) emits no
  AddPath delta. No AddPath builder or sync branch consults
  `nexthop_reachable` (`route.rs:4917`, `13252-13272`, `13905-13916`,
  `14926`, `15071`, `15134`, `15221`, `15484`); `select_best_path`
  (`2204`) withdraws from plain peers only. RFC 4271 §9.1.2.1 makes an
  unresolvable route ineligible.
- Scenario: eBGP AddPath peer P with next-hop-self holds paths A (NH x)
  and B (NH y) rewritten to self; x and y both become unreachable. The
  prefix is withdrawn from the FIB and from plain peers; P still holds A
  and B via us and forwards into a drop. With one next-hop lost, P may
  prefer the path we no longer forward on.
- Fix direction: have the NHT re-evaluation report the flipped rows as
  AddPath deltas (add/withdraw per `local_id`), and gate the AddPath
  builders on `nexthop_reachable`.

### 24. P2 CONFIRMED — a `route-target import` change is silently ineffective; export re-tag skips sibling re-import and RTC-skipped peers

- `inst.rs:4662-4683` (`RibRx::VrfRouteTargets`) assigns the import RT
  sets and re-tags only when an export set changed; import RTs are read
  solely at ingest (`vrf/inst.rs:464-513` `dispatch_import_v4`); nothing
  walks `shard.v4vpn/v6vpn`, no route-refresh is sent to PE peers
  (`peer_send_route_refresh`'s only caller is `peer.rs:3889`), and
  `runtime_structure_eq` (`vrf_config.rs:423-437`) excludes RTs so the
  VRF is not respawned. `retag_vrf_exports_v4/v6` (`inst.rs:4003-4200`)
  never calls `dispatch_import_*` / `dispatch_withdraw_import_*`, and the
  RTC "skip without withdrawing" (`route.rs:5539-5542`, `5721-5724`)
  leaves the old-RT advertisement in `adj_out` and on the wire.
- Scenario: operator adds `route-target import 65000:200` to VRF blue;
  existing VPNv4 routes carrying it are not imported (no CE advertise)
  until the remote PE re-sends. Removing an RT leaves already-imported rows
  in the VRF and at CE peers. Changing VRF red's export RT does not
  withdraw red's routes from VRFs that imported under the old RT.
- Fix direction: on an import-RT change, re-run the import filter over the
  VPN tables for that VRF (add and withdraw); on an export-RT change,
  re-dispatch the re-tagged rows through the import path and withdraw the
  RTC-filtered peers' stale rows.

### 25. P2 CONFIRMED (knob-gated) — with `peer-sharding` at N=1 the session-up dump is never recorded in the PET's Adj-RIB-Out, so every dump-learned prefix is unwithdrawable

- `peer.rs:2193-2198` spawns the PET and then runs `route_sync`;
  `route_sync_ipv4` (`route.rs:15024-15040`) sends `RecordAdjOut` to the
  group task at gate-on and records main's `peer.adj_out`, but never the
  PET; the `ZEBRA_BGP_SYNC_CHUNK` cursor (`14902-14974`) records neither
  engine. `peer_egress.rs:245-255` `Engine::withdraw` sends only if its
  own `adj_out` held the prefix, and at PET-on every v4 withdraw goes via
  `fan_advertise_to_pets` (`route.rs:5173-5176`, `5210-5232`). The N>1
  twin records (`inst.rs:6778-6790`). `zebra-bgp-sharding.yang:75` makes
  `peer-sharding` a YANG knob with `rib-sharding` unset (N=1).
- Scenario: `router bgp sharding peer-sharding true`; peer B establishes
  after P is in the Loc-RIB and gets it from the dump; the upstream
  withdraws P; the PET finds no row and sends nothing; B forwards P to us
  forever. Only prefixes whose attributes changed after B came up are ever
  withdrawable.
- Fix direction: send the PET a `RecordAdjOut` per dumped prefix (or have
  the PET perform the dump).

### 26. P3 CONFIRMED — VRF-imported rows tie-break on our router-id and RD registration order

- `vrf/inst.rs:2357-2385` builds imports with `router_id: self.router_id`,
  `ident: ORIGINATED_PEER`, `remote_id: import_id(rd)` (`2252`, RD
  registration order), and `stale: false` (`2385-2400`, v6 twin). Two
  dual-homed imports with equal attributes and no RR-stamped ORIGINATOR_ID
  (direct PE-PE iBGP) tie through (f)/(g) and are decided by which RD was
  seen first; a direct CE path is compared against our own identifier; a
  stale PE's import is not depreferenced against a fresh sibling-RD import
  and CE peers receive LLGR_STALE-tagged routes.

### 27. P3 CONFIRMED — Flowspec and SR-Policy egress skip the shared gates

- `route_update_flowspec` (`route.rs:11094-11150`) has no
  `community_suppresses_advertisement`, no LLGR gate in
  `route_advertise_flowspec_to_peers` (`11167`), no out-policy.
  `srpolicy_reflect` (`10516`) / `reflect_attr` (`sr_policy.rs:891`) honor
  NO_ADVERTISE only (NO_EXPORT leaks to eBGP), never call
  `ebgp_egress_aspath` (no local-AS prepend toward eBGP, RFC 4271 §5.1.2),
  and `route_sync_srpolicy` (`10862`) replays only local policies.

### 28. P3 CONFIRMED — family-specific next-hop divergences that commit silently

- LU4/LU6 ignore `next-hop-unchanged` and route-server-client
  (`13440-13447`, `13527-13533`); EVPN/MUP/FS ignore `next-hop-self` for
  iBGP; the YANG admits all knobs for every `afi-safi` name.
- v4-unicast/VPNv4 on a v6-only session: `local_addr_v4 = None` →
  `ctx.router_id` on the wire (`12838`) even when the router-id is not
  routable; the v6 builder refuses to emit `::` instead.
- VPNv6 over v4 transport uses the interface global v6 (`13036-13040`),
  not the RFC 4659 IPv4-mapped form LU-v6 uses (`13525`); with no global
  v6 the upstream next-hop is left untouched (`13062`).

### 29. P3 CONFIRMED — ENHE member without an observed link-local is skipped at flush after Adj-RIB-Out recorded the send; gate-on engines ignore ENHE

- `update_group.rs:876-897` `continue`s per member when `enhe_v6` is
  `None` (asserted as intended by `flush_job_enhe_per_member_next_hops`),
  after `route.rs:5555` recorded `adj_out`; `inst.rs:4427-4435` only
  records the later `AddrAdd`, no re-advertise; the sync dump
  (`route.rs:15045-15053`) falls back to legacy encoding with
  NEXT_HOP = router-id. `group_egress.rs:309-313` and `peer_egress.rs`
  never compose an ENHE next-hop (env-gated).

### 30. P3 CONFIRMED — `suppress-fib-pending` is bypassed by the N>1 session-up dump

- `shard/dispatch.rs:170-260` (`handle_dump_v4`) has no fib-pending gate
  and `DumpParamsV4` (`shard/msg.rs:230`) carries none; `route.rs:15605-15620`
  skips the gated N=1 dump when `v4_via_pool`. A new peer learns prefixes
  the dataplane has not confirmed; the later release re-sends them.

### 31. P3 PLAUSIBLE — `multipath_eligible_agrees_with_is_better` (`route.rs:25609`) does not pin the lockstep property

- Two equal-cost fixtures only; a step added to `is_better` that both tie
  on, or one deleted from `multipath_eligible`, still passes. Needs pairs
  differing in exactly one ladder field each.

### 32. P3/P4 CONFIRMED (env-gated / cosmetic) — gate-on PET starves AddPath v4 peers and has no LLGR gate; VPNv6 AddPath never records `adj_out.v6vpn`

- `route.rs:4711-4714` returns before the AddPath fan under
  `ZEBRA_BGP_PEER_TASK`; `fan_advertise_to_pets` (`5191-5210`) iterates
  plain idents only; PET `Engine::advertise` (`peer_egress.rs:207-235`)
  never reads `rib.stale` (the recorded group-engine LLGR item's "every
  sibling has the gate" is wrong for the PET). VPNv6 AddPath
  (`5820-5835`, `13359-13372`) sends without recording; only
  `route_sync_vpnv6` (`15275`) records, so `advertised-routes` / PfxSnt
  drift (the recorded "plausible" item, confirmed display-only).

### Found while fixing #1 (FIXED on branch `bgp-dynamic-peer-type`: `try_dynamic_accept` now derives `peer_type` from the group's remote-as the way `interface_neighbor.rs` does; regression test `accepted_dynamic_peer_takes_its_type_from_the_group_remote_as` and `bgp_dynamic_neighbors` asserts `route_type eBGP` / `as_path 65001`)

- **P1 CONFIRMED (probe) — a dynamic listen-range peer is typed iBGP
  regardless of the group's `remote-as`.** `try_dynamic_accept`
  (`peer.rs:3770-3850`) builds the peer with `Peer::new`, which hard-codes
  `peer_type: PeerType::IBGP` (`peer.rs:1361`), and neither it nor
  `apply_inherited` re-derives the type from `remote_as` versus `bgp.asn`;
  the only derivation for dynamic peers is the group sweep in
  `config_neighbor_group_remote_as`, which runs on a later config change,
  never on accept. Probe: group `A remote-as 65002` under local AS 65001,
  range `10.1.0.0/24` bound to `A`, `try_dynamic_accept` with a loopback
  stream → `remote_as == 65002` but `peer_type == IBGP`. Consequences for
  every dynamic eBGP peer: the parser keeps its LOCAL_PREF (the #1 fix
  keys on the reader's `peer_type`), egress skips the AS_PATH prepend and
  the eBGP next-hop rewrite, its routes rank as iBGP (distance 200, the
  iBGP-to-iBGP rule blocks relaying them to iBGP peers, LOCAL_PREF is
  defaulted onto them) and the iBGP-only attributes are not stripped
  toward it. The dynamic-neighbor BDDs (`bgp_dynamic_neighbors`,
  `bgp_dynamic_nbr_policy`, `bgp_dynamic_nbr_md5`) all use an eBGP group
  but assert route presence only. Fix: derive `peer_type` in
  `try_dynamic_accept` exactly as `interface_neighbor.rs:188` does; the
  probe becomes the regression test.

### Below the cap (one line each, all read-confirmed)

- `apply_soft_in_peer` (`peer.rs:3842-3890`): with
  `soft-reconfiguration inbound` set, an inbound policy edit on
  v6/VPNv6/LU/EVPN replays nothing and also skips the ROUTE-REFRESH
  fallback, so it is silently ineffective until reset; without
  soft-reconfig the refresh makes it work.
- `DumpBarrierV4` (`inst.rs:640-700`) is never cancelled on peer-down;
  after a fast bounce the old dump's acks record phantom rows into the
  reused slot and emit a premature ipv4-unicast EoR on the new session
  (`inst.rs:6794-6797`).
- `flush_done_ipv4` (`update_group.rs:1095-1140`) drops deferred
  withdraws for members that left the group mid-flight;
  `reassign_all_update_groups` (`config.rs:190-209`) moves Established
  peers whose `adj_out` row `V4Batch::withdraw` already removed, so the
  withdraw is lost.
- `allowas-in` / `enforce-first-as` edits (`config.rs:913`, `1080`) run no
  soft-in; policy-out edits replay v4/VPNv4/EVPN only and are not
  family-scoped (`route.rs:6801-6826`); accepted-but-inert: neighbor
  `enabled`, `vpnv6 next-hop-self|unchanged`, `evpn next-hop-self`,
  `labeled-unicast next-hop-unchanged`.
- `show bgp -j` (`show.rs:986`, `render_unicast_table`) stamps
  `best: true` on every row, so the JSON table cannot say which of a
  prefix's candidates was selected; the per-prefix `bgp_route_json`
  reports the real flag. Found while writing the LOCAL_PREF BDD: a
  best-path assertion on the JSON passed against the wrong candidate.
- `mirror_v4_delta` (`route.rs:4806-4822`) never refreshes
  `nexthop_reachable` on main's `v4.0` replica for NHT re-evaluations, so
  `show bgp ipv4` shows stale reachability at N>1 (cosmetic).
- (From the parallel review, gate-on only, PLAUSIBLE here) group engine
  split-horizon: when member A becomes the source of a prefix's new best,
  `group_egress.rs:275-320` fans the new bytes to everyone but A and never
  withdraws the previous advertisement from A, so A keeps the old path.
- Empty per-RD Loc-RIB tables also leak on the remove/NHT paths
  (`shard/mod.rs:307,384`, `inst.rs:5759,5767`, `route.rs:3465,3494`),
  extending the recorded `entry(rd).or_default()` item.

### Gaps (not bugs, consequences only)

- RFC 4271 §9.1.2.2 step (e), IGP metric to the next-hop, is absent (NHT
  knows reachability only): with two PEs reflecting equal-attribute paths
  the exit is the lowest ORIGINATOR_ID, not the nearest, and multipath can
  bundle a far PE with a near one. RFC 4456 §9 cluster-length step is
  commented out (`route.rs:2375-2389`), churn only.
- `neighboring_as()` (`crates/bgp-packet/src/attrs/aspath.rs:851`) skips a
  leading AS_SET, so MED is compared between `{a,b} c` and `{d} c`; FRR
  treats a leading set as non-comparable. AS_SET is deprecated.

## Verified sound (so it is not re-checked)

- AS_PATH `length` is recomputed after every inbound rewrite (parse, AS4
  merge, local-as ingress prepend, policy prepend, `replace_as_mut`);
  AS_SET counts 1, confederation segments 0; allowas-in occurrence and
  origin modes.
- Shard and main select through the same `is_better`; implicit replace
  rides `selected` with attr-pointer dedup; AddPath change rides `added`.
- `update()` local_id reuse: replaced rows keep their id, new ids are
  allocated after extraction; on v4-unicast the exact-id withdraw is
  immediate or replayed before the re-run flush, so a reused id's withdraw
  precedes its announce.
- Every `remove()` caller runs `select_best_path`, which reclaims empty
  prefix entries; missing MED = 0; `weight` is never wire-derived.
- Batch precompute and apply pick the same canonical member (first
  non-source, non-LLGR in ident order): no stale seeded memo.
- `local_addr` comes from the socket before `attach`; `router_id`,
  `srv6_ipv6_export`, `as_sets_withdraw`, `interface_addrs` are
  instance-global; `remote_as` reaches the transform only through knobs
  that are in the signature; `route_server_client` is in the signature
  and folded into `unicast_next_hop_unchanged`.
- Flush reads `as4` / `extended_message` from the group signature; per-NLRI
  split-horizon, per-member LLGR, per-member ENHE next-hop shape.
- VPNv6 rows always carry `BgpNexthop::Vpnv6`, so the v6 SRv6 Prefix-SID
  strip and strict-encap gate never touch VPNv6.
- Negotiation: AddPath send gated on `addpath_send_implemented` in the
  OPEN and in `cap_addpath_recv`; `membership_enroll` recomputes per
  session; the PET is dropped on leaving Established and re-spawned with
  the new session's AddPath flag.
- v6-unicast and LU event loops read the full candidate table and diff
  `adj_out` ids (the 2026-06-14 fix holds); sync and event tables agree for
  v4, v6, VPNv4, VPNv6.
- N>1 DumpV4 versus a concurrent withdraw: one FIFO result channel
  (`shard/pool.rs:49-65`), shard-ordered DumpV4 → Withdraw, and
  `process_shard_result` peels `DumpDoneV4` before reducing
  (`inst.rs:6740-6800`); the earlier note about an adj_out-miss window
  does not hold on `main`.
- Peer-down at N=1 and N>1: `route_clean` / `handle_peer_down` withdraw
  every family including AddPath, clear all per-family `adj_out`, VPN/EVPN
  caches and timers, `rtcv4/6` / `eor`, drop the PET, clear `sync_v4`,
  detach after clean; slot reuse purges membership.
- ORIGINATOR_ID set-once + CLUSTER_LIST prepend and the eBGP strip are
  byte-identical across v4, v6, LU, EVPN, MUP, FS, SR; split-horizon and
  the iBGP-iBGP gate identical in all builders; NO_ADVERTISE/NO_EXPORT
  gate before out-policy in v4, v6, VPN, LU, EVPN, MUP; LLGR §4.3 gate on
  every AddPath advertise and sync path.
- `route_clean` covers v4/v6/VPNv4/VPNv6/EVPN/MUP/LU4/LU6/Flowspec/BGP-LS
  Adj-RIB-In and -Out, the VPN/EVPN caches and `rtcv4/rtcv6`.
- Codec: EVPN MP_REACH next-hop on a v6 session is 16 bytes; LU-v4 over
  v6 emits a 16-byte next-hop; LU-v6 over v4 uses the 6PE mapped form;
  VPNv4 SRv6 rows keep the locator next-hop in both builders.
- `maximum-paths` changes re-select and re-install the FIB for every
  v4/v6 prefix; RD change / VRF delete / `no afi-safi vpnv4` /
  `label-mode` change purge old exports and withdraw from PE peers and
  sibling VRFs; `local-as`, `otc-local-role`, `route-server-client`,
  `ttl-security`, `ebgp-multihop` changes bounce the session.
- No crafted-UPDATE panic in the selection or ingest code.

## Test and BDD gaps this review exposes

- No RR BDD has a non-client iBGP neighbor receiving a client's route.
- No BDD puts two peers with different `next-hop-self` /
  `next-hop-unchanged` / out-policy in the same update-group (same
  `local_addr`); `bgp_vrf_neighbor_next_hop` separates them by subnet.
- No test feeds LOCAL_PREF / ORIGINATOR_ID / CLUSTER_LIST from an eBGP
  peer.
- No selection test uses three candidates with mixed neighbor ASes and
  MED, or re-feeds an unchanged route.
- No test asserts which path a plain peer is advertised under
  `maximum-paths`.
- No EVPN AddPath test with two candidates and a flip; no LU AddPath test
  with two mutual AddPath peers.
- No LLGR/PIC test for VPNv6 or EVPN stale expiry, and no GR test where
  the ipv4-unicast EoR arrives before the VPNv4 refresh.
- `signature_fields_each_distinguish` cannot catch a field that does not
  exist; a complementary test should assert that every peer field
  `sync_ctx()` / `route_update_ipv6` reads is either in the signature or
  instance-global.

## Probes

The failing probe tests that pin findings 1, 2, 3, 4, 5, 6, 10, 11, 12,
14 and 15 live in one `#[cfg(test)] mod adversarial_probe_tests` that was
appended to `zebra-rs/src/bgp/route.rs` during the review and removed
afterwards; the module is saved as `adversarial_probe_tests.rs` in the
review session's scratchpad and is written against the helpers already in
`route.rs` (`Peer::new`, `PeerMap`, `membership_enroll`,
`update_group::attach`, `route_advertise_to_peers*`, `LocalRibTable`).
Each probe asserts the RFC-conformant outcome and fails on `main`; they
are the starting point for the regression tests of the corresponding
fixes. Twelve of the thirteen probes fail on `main`; the v4 control for
finding 5 passes, which is what isolates the v6 drift.
