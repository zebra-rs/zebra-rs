# BGP code review findings (`zebra-rs/src/bgp/`)

Whole-directory review of `zebra-rs/src/bgp/` (46 files, ~69k lines) at extra-high
effort. Ten independent finder angles produced 68 candidates; each surviving
candidate was checked by an independent adversarial verifier that had to name a
concrete trigger and quote the decisive lines, then a fresh gap sweep added more.

**Result: 34 confirmed correctness bugs + 15 confirmed cleanup items.**
**Status 2026-07-18: top-13 fixed and merged** (PRs #1962, #1972, #1981,
#1984, #1987, #1991, #1997, and the finding-#9 branch); fixes below the
cap remain open. Three
candidates were refuted (two vty-disconnect "panics" are guarded by detached
forwarding tasks; the N>1 BSID resync is covered by a mirrored winners replica).

Line numbers are as of the review (branch `bgp`, tip `77efd00c`). All findings
were confirmed against the current tree, not old commits.

Two recurring root causes account for most of the correctness set:

1. **Withdraw / teardown paths that don't propagate or clean up** — received
   withdraws not fanned to peers, empty-selection deltas not withdrawn, RD-aliased
   VRF imports, and caches / snapshots / timers that outlive the session that
   owned them.
2. **Per-peer egress knobs that bypass the update-group signature** — a transform
   memoized from the first group member leaks to divergent members
   (ipv6 encap-type, vpnv4 next-hop-self/unchanged, as-override, …).

Both keep re-originating from the same duplicated code (the four copy-pasted
Loc-RIB tables and the hand-mirrored v4/v6 twins). Generalizing those is the
deepest fix.

---

## Top 15 (ranked most severe first)

### 1. Daemon crash: `fsm()` unwrap on a removed peer slot — `peer.rs:1801` — FIXED (PR #1962)

`fsm()` does `peer_map.get_mut_by_idx(id).unwrap()` with no guard, and
`process_msg` (`inst.rs:2148`) dispatches `Message::Event(ident, event)` to it
unconditionally. `remove_by_key` (`peer_map.rs:81`) sets `peers[idx] = None`
without shrinking the Vec or draining the event channel, and events carry a bare
`usize` with no generation tag. BGP events (`self.rx`) and config deletes
(`self.cm.rx` → `config.rs:376 peers.remove`) are separate arms of one `select!`.

**Trigger:** an Established neighbor's reader queues `Event::UpdateMsg(ident)`
into the 8192-deep channel; an operator `no neighbor X` removes `peers[ident]`;
the next dispatch hits `get_mut_by_idx(ident).unwrap()` on `None` → **panic
crashes the whole daemon, killing every session.** Second path: dynamic-peer reap
(`inst.rs:2385`) plus a queued timer/dial event.

### 2. 4-byte-ASN peers can never establish — `peer.rs:2086` — FIXED (PR #1972, full RFC 6793)

After the AS4-aware ASN check passes (`2055-2058`, folds the AS4 capability), the
code re-compares the raw 2-octet field `packet.asn as u32 != peer.remote_as` and
returns `State::Idle`. Per RFC 6793 a speaker with ASN > 65535 sends AS_TRANS
(23456) in the 2-byte My-AS field.

**Trigger:** `remote-as 4200000000` → `23456 != 4200000000` → Idle on every
attempt, no NOTIFICATION. **Any 4-byte-ASN peer is permanently rejected.**
Outbound is also broken: `peer.rs:2947` truncates local-as to `u16` instead of
sending AS_TRANS. Fix: delete the redundant `2086` comparison.

### 3. VRF delete → cross-VRF traffic leak — `inst.rs:2440` — FIXED (PR #1981)

`apply_vrf_commit_diff`'s despawn arm frees and immediately reclaims the VRF's
MPLS label (`2464-2468`) but never purges the VRF's exported rows
(`ORIGINATED_PEER` under its RD) from `shard.v4vpn`/`v6vpn` and never withdraws
them from PE peers. The VRF task's `Shutdown` is a bare loop-break
(`vrf/inst.rs:1103`), and a late `WithdrawExport` is dropped because
`vrfs.remove` already ran (`5451-5460`). Label reuse is immediate (`label.rs:122`,
free-list pops lowest first).

**Trigger:** delete a VRF whose CE routes were exported as VPNv4 → stale rows stay
advertised to remote PEs; the freed label is handed to the next VRF, whose
`DecapVrf` ILM binds it → **remote PEs still forwarding to the old advertisement
decap into the wrong VRF.**

### 4. Dual-homed L3VPN withdraw blackholes the survivor — `vrf/inst.rs:1444` — FIXED (PR #1984)

`handle_import_v4` stores every import under `(prefix, id 0, ORIGINATED_PEER)`
ignoring the origin RD (`1310-1351`), and `handle_withdraw_import` also ignores
its `rd` argument, removing that single row (`1444-1446`). Imports of one prefix
from two RDs alias to one row. The global side's `select_best_path_vpn` is
strictly per-RD, so the withdraw of the first RD fires `WithdrawImport` even
though the other RD still has a winner.

**Trigger:** a VRF imports `10.1.0.0/24` from PE1 (RD 1:1) then PE2 (RD 2:2) — the
second replaces the first row; PE1 withdraws → the VRF removes the row now holding
**PE2's still-valid route → CE-side blackhole**, and nothing re-imports RD 2:2's
winner until an unrelated event.

### 5. EVPN received-withdraw never propagated to peers — `route.rs:7955` — FIXED (PR #1987)

`route_evpn_withdraw` (handler for received EVPN MP_UNREACH, also used by
peer-down cleanup) recomputes best-path but its only peer-facing action is
withdrawing *our own* originated routes; `route_evpn_export_selected` is
dataplane-only. `route_advertise_evpn_to_peers` early-returns on empty selection,
and `route_withdraw_evpn_to_peers` is only called from local-origination paths.
The v4 and MUP withdraw paths both propagate; EVPN never got it (the comment at
`10437` falsely claims it does).

**Trigger:** EVPN route reflector — client A advertises a Type-2 which the RR
reflects to B; A withdraws it → RR removes it locally but **B never receives the
withdraw and keeps forwarding to the departed host's stale VTEP** until the B
session bounces. Also affects eBGP EVPN transit and both peer-down cleanup arms.

### 6. IPv6 empty-selection never withdraws from peers — `route.rs:6331` — FIXED (PR #1991)

`route_ipv6_update` gates the peer fan-out on `if !selected.is_empty()`
(also VPNv6 at `6359`), so an UPDATE whose best-path delta empties the selection
never sends MP_UNREACH. The v4 twin routes empty-selected through
`apply_ipv4_advertise_job`'s withdraw branch. Empty deltas are real: inbound-policy
deny of the last candidate (`dispatch.rs:627-634`) or the NHT reachability gate
(`route.rs:1777`).

**Trigger:** peer re-advertises a v6 prefix with an unreachable next-hop → local
FIB entry deleted but **no MP_UNREACH sent → other peers hold and forward on the
stale v6/VPNv6 route indefinitely.**

### 7. ipv6 encapsulation-type missing from UpdateGroupSig — `update_group.rs:350` — FIXED (PR #1997)

`signature_of` omits per-peer `afi-safi ipv6 encapsulation-type`
(`ipv6_srv6_encap`/`ipv6_srv6_strict`), but `route_update_ipv6` uses it to strip
the SRv6 Prefix-SID (`route.rs:11333`) and suppress SID-less routes (`11395`).
The post-transform outcome is memoized per update-group (`4972`) and one canonical
encode is fanned to all members.

**Trigger:** an SRv6-encap PE peer and a plain CE peer land in one ipv6-unicast
group → the outcome computed from whichever iterates first is reused for both, so
the CE receives the route with the **provider SRv6 service SID kept — the code's
own comment (`11313`) calls this fatal: the CE tracks an unresolvable provider
locator and blackholes.** Order-dependent; incremental (post-sync) advertisements
only.

### 8. vpnv4 next-hop-self/unchanged shared through the group memo — `route.rs:11110` — FIXED (PR #1997)

Per-peer `afi-safi vpnv4 next-hop-self`/`next-hop-unchanged` select the egress
NEXT_HOP (`11110-11115`, via per-peer `sync_ctx`) but are not `UpdateGroupSig`
fields, while `(Ip, MplsVpn)` is a tracked family whose outcome is memoized per
group id from the first-iterated member. The adjacent comment (`10939-10943`)
warns explicitly against adding per-peer state to the memoized path.

**Trigger:** an Inter-AS Option-B ASBR with `next-hop-self` toward PE1 but not PE2
(both same group) → one PE is sent the **wrong NEXT_HOP → VPN traffic blackholes.**

### 9. Family-blind SRv6 service-SID selection at FIB install — `route.rs:701` — FIXED (fib-install + show sites; nht_target keeps first-SID by design, see its doc)

`select_fib_entry_v4` (`701`) and `select_fib_entry_v6` (`972`, `980`) use
first-SID `srv6_l3_sid()`, whose own doc (`bgp_attr.rs:166`) warns consumers to
use `srv6_l3_sid_for_dest`. Commit 49515500 fixed only the MUP sites; the
L3VPN/unicast install siblings still take the first SID regardless of family.

**Trigger:** a remote PE advertises a VPNv4 route whose SRv6 L3 Service TLV lists
`[End.DT6, End.DT4]` (a legal split pair) → `select_fib_entry_v4` H.Encaps v4
traffic toward the **End.DT6 SID, whose decap only serves IPv6 → blackhole.**
Mirror-image for v6. Same family-blind pattern at `nht.rs:203`, `show.rs:1847`.

### 10. Phantom `Established` state from an un-cancelled advertise timer — `route.rs:10063` — FIXED (timers cancelled in route_clean + handlers no longer force Established)

`route_clean` (peer teardown) clears the `cache_vpnv4`/`cache_vpnv6` forward maps
but not their debounce timers (the EVPN teardown at `10582-10584` clears
forward + reverse + timer). A `cache_vpnv4_timer` armed before a bounce fires
after teardown; its handler `fsm_adv_timer_vpnv4_expires` returns
`State::Established` unconditionally (`peer.rs:1905`), dispatched with no state
gate (`peer.rs:1761`), and `fsm()` applies it blindly (`peer.rs:1804`).

**Trigger:** an iBGP PE advertises a VPNv4 route (timer armed), the session drops
within the ~5 s debounce, the timer fires while the peer is Idle → the peer is
**forged into `Established` with no session** (membership enroll, route-sync into a
null `packet_tx`, update-group attach), corrupting the real reconnect until the
phantom's hold timer tears it down.

*(The originally-suspected reverse-map mis-cancel is refuted — `flush_vpnv4` clears
the reverse map at reconnect. The un-cancelled timer is the real, worse payload.)*

### 11. path-id-0 withdraw wildcard desyncs Adj-RIB-In vs Loc-RIB — `adj_rib.rs:77` — FIXED (In direction is exact-match; Out keeps the wildcard)

`AdjRibTable::remove` treats `id == 0` as a whole-prefix wildcard
(`self.0.remove(&prefix)`) when no candidate's ID matches. The wire path-id is
parsed unvalidated (`nlri_ipv4.rs:20`), while the Loc-RIB `remove` (`route.rs:1726`)
matches `remote_id == id` exactly.

**Trigger:** an AddPath peer that announced path-ids 1 and 2 sends a withdraw with
path-id 0 (wire-legal, never announced) → **all Adj-RIB-In candidates are wiped
while the Loc-RIB keeps both paths.** Amplifier: peer-down cleanup
(`10042-10058`) derives withdraws solely from Adj-RIB-In, so the orphaned Loc-RIB
rows survive even session teardown, stuck in the FIB. Trigger is a
nonconformant/malicious (attacker-controlled) peer.

### 12. Deleting an out-policy leaves the stale snapshot denying everything — `config.rs:713` — FIXED (Unregister now emits a clearing PolicyRx)

`config_afi_safi_policy_out` on Delete only sends `Unregister`, and the policy
actor emits no `PolicyRx` on `Unregister` (`policy/inst.rs:379`), so neither
`rebuild_out_policy` nor `apply_soft_out_peer` runs on unbind (both fire only from
the `PolicyRx` arms).

**Trigger:** `delete … neighbor X afi-safi ipv4 policy out DENY-ALL` → `out_policy`
still holds the resolved DENY-ALL, so v4-unicast egress **keeps denying every
prefix**; it survives an FSM bounce, and the watch is gone so even editing the
policy no longer notifies this peer — the neighbor stays route-less until a new
out-policy name is bound. (v6/VPN families: the name-gate stops the *content* but
the missing re-advertise leaves suppressed routes suppressed.)

### 13. Missing lowest-BGP-Identifier tie-breaker — `route.rs:1908` — FIXED (is_better compares BGP Identifier / ORIGINATOR_ID; slot index and path-id are final deterministic fallbacks)

The final best-path tie-break compares the internal peer slot index `ident`
(assigned in registration order, `peer_map.rs:68`) then `remote_id` (which is the
**AddPath path-id, not a router-id**). The OPEN-learned identifier is carried on
every path as `BgpRib.router_id` but never read in `is_better`. RFC 4271
§9.1.2.2(f) lowest-BGP-Identifier is absent, and `Reason::RouterId` is a misnomer.

**Trigger:** two equal iBGP paths → the winner is whichever neighbor got the lower
slot index; a runtime-added neighbor always loses this tie. **Best-path becomes
order-dependent** and can disagree with RFC-conformant routers.

### 14. NO_ADVERTISE / NO_EXPORT ignored on labeled-unicast — `route.rs:11637`

`community_suppresses_advertisement` is called only for v4/v6 unicast, EVPN, and
MUP (grep confirms sites `5032`, `8309`, `11067`, `11237`). `route_update_labelv4`
(`11637-11713`) and `route_update_labelv6` (`11719-11795`) omit it, and no
compensating filter exists in `route_advertise_labeled` or the sync dumps.

**Trigger:** a SAFI-4 route carrying NO_ADVERTISE or NO_EXPORT is **still
advertised on the labeled family — an RFC 1997 violation / route leak.**

### 15. Graceful Restart advertises a 1-second Restart Time — `peer.rs:2924`

The GR OPEN emitter advertises Restart Time = the stored config value, but
`config_restart` (`config.rs:2933`) stores only an enable marker of `1` (there is
no restart-time leaf in the neighbor YANG), and no default is applied.

**Trigger:** any GR-enabled session advertises **Restart Time = 1 s** → an
RFC 4724 helper flushes retained routes after ~1 s → graceful restart provides no
forwarding continuity. (Not a regression — pre-remodel code advertised the same
value.) Fix: apply a sane default (e.g. 120 s, clamped) or add a real config leaf.

---

## Also confirmed — correctness (verified, below the cap)

- **SR-Policy RR withdraw never propagated — `route.rs:8852`.** A pure RR that
  reflects SR Policies it does not itself consume (`usability != Usable`, RT
  targets a client) reflects every UPDATE (`8798`, before the usability gate) but
  never stores them (`8802` early return), so the withdraw reflection gated on
  `removed` (`8852`) is skipped, and the peer-down sweep (`10672`) only iterates
  stored candidates. Clients keep stale SR Policies / Binding-SID state until reset.
- **SR-Policy stale on retarget — `route.rs:8802`.** A Usable→NotUsable
  re-advertisement of the same NLRI (controller re-homes the policy's RT to another
  headend) early-returns before touching the DB; the previously-installed candidate
  and its BSID FIB state remain. No SAFI-73 adj-in exists to force an implicit
  withdraw.
- **Advertise-cache forward/reverse desync — `update_group.rs:616`.** `send_ipv4`
  / `send_ipv6` insert an NLRI into a new attr bucket without evicting it from the
  bucket the reverse map previously pointed at. Two attr changes in one MRAI window
  leave it in both buckets; a subsequent withdraw purges only one → **flush
  re-announces a just-withdrawn prefix**; the HashMap drain order can also ship the
  old attr after the new one.
- **Signature knobs applied live without regroup — `config.rs:961`.**
  `apply_as_override` / `apply_remove_private_as` / `apply_route_reflector_client`
  mutate signature-bearing state on a live Established peer with no detach/attach
  (regroup happens only at the Established transition and in the egress-script
  handlers) → the memoized first-member transform is applied to divergent
  group-mates until a bounce.
- **soft-out/soft-in only replay v4u/VPNv4/EVPN — `route.rs:5575`.** IPv6-unicast,
  VPNv6, and labeled-unicast are never re-evaluated even though v6 egress applies
  per-AFI out-policy live; `clear bgp ipv6 … soft out` and a received v6
  ROUTE-REFRESH silently no-op. Related: soft-in replays the VPNv4 table through
  the hardcoded ipv4-unicast policy (`route.rs:5970`) instead of the vpnv4 binding.
- **soft-in re-install strips SRv6 encap — `peer.rs:3306`.** `apply_soft_in_peer`
  builds `BgpTop { nexthop_cache: None }` then runs `fib_install_v4`, which
  degrades an SRv6-inherited winner to a plain, unencapsulated FIB entry
  (`route.rs:780`). `table_map_resync` wires `Some(cache)` with a comment warning of
  exactly this. Default N=1 path; needs soft-reconfiguration-inbound.
- **LLGR-stale route fanned to non-LLGR peers — `group_egress.rs:328`.** With
  `ZEBRA_BGP_EGRESS_GROUP_TASK=1`, `Engine::fan` sends to all members with no LLGR
  gate; the signature intentionally excludes LLGR so capable and non-capable peers
  share a group. Every sibling path has the RFC 9494 §4.3 gate. Trigger: a
  v4-unicast route arriving with the LLGR_STALE community from an upstream helper.
- **Stale in_policy snapshot survives peer-down — `dispatch.rs:792`.** At N>1 the
  replicated inbound-policy snapshot is never cleared on peer-down (only ever set
  via `PolicyReplace{Some}`), so a re-created same-address neighbor's reused index
  is filtered through the **deleted neighbor's route-map** instead of default-permit.
- **Adj-RIB-Out accumulates stale rows on best-path flip — `adj_rib.rs:51`.**
  `Out::add` dedups by `local_id`, which changes when a different candidate wins,
  so a flip appends a second row instead of replacing. `show … advertised-routes`
  shows duplicates; in the gate-on egress modes an A→B→A flip with unchanged attrs
  is suppressed by the `ptr_eq` check (`peer_egress.rs:228`), leaving the peer
  holding B.
- **RTC MP_UNREACH withdraw ignored — `route.rs:10008`.** `MpUnreachAttr::Rtcv4`
  / `Rtcv6` fall into the `_ => {}` catch-all; membership is never removed from
  `peer.rtcv4/rtcv6`, so zebra keeps advertising VPN routes tagged with a withdrawn
  RT for the session's life.
- **EVPN SR-MPLS-P2MP BUM has no datapath — `route.rs:2617`.**
  `bum-tunnel-type sr-mpls-p2mp` is still accepted (`config.rs:2325`) but flood is
  suppressed and the surviving replication tee is SRv6-only (`CradleReplAdd` is
  `Ipv6Addr`-typed) → BUM silently dropped. Related: a SID-less / plain-IR remote
  IMET is excluded from the BUM domain in srv6-p2mp mode (`route.rs:7280`).
- **Interface-neighbor delete leaks + stale listener MSS — `interface_neighbor.rs:257`.**
  Peers are keyed by materialization-time ifindex; a link deleted-and-recreated
  (new ifindex) leaves a zombie peer that re-dials forever, since the delete arm
  resolves via the current map. The delete also omits
  `apply_tcp_mss_refresh_all`/`clear_peer_listener_auth`, stranding a group-inherited
  TCP-MSS clamp on the shared listener. (ip-transparent half refuted — the group
  union is recomputed directly.)
- **vpnv6 next-hop-unchanged silently ignored — `route.rs:11272`.** Accepted by
  config for VPNv6 but only consulted for `(Ip, MplsVpn)` → no-op (VPNv6 always
  next-hop-selfed). Documented as VPNv4-only in YANG, but the config is still
  accepted silently. Same v6 gap for next-hop-self and no `vpnv6_service_label`.
- **ConnectedSubnets refcount desync — `connected.rs:57`.** Blind per-subnet
  +1/−1 keyed only by network, over a non-idempotent AddrAdd/AddrDel stream (RIB
  redistributes every AddrAdd EVENT; `interface_addrs` is set-based by contrast). A
  duplicate/out-of-order AddrDel can deflate the count below the live-address count
  → subnet dropped while an address is still live → a legitimate single-hop eBGP
  peer held down by the connected-check.
- **Unbounded growth (memory over uptime):** `peer_map.rs:81` `remove_by_key`
  leaks the map key + Vec slot on dynamic-peer churn; `adj_rib.rs:397`
  `entry(rd).or_default()` on remove/read/probe paths inserts empty per-RD tables;
  `store.rs:37` the attr intern store keeps a second deep copy per attr and never
  sweeps dead `Weak` entries.
- **EVPN deny purges the just-stored Adj-RIB-In entry — `route.rs:7853`.**
  Observable today as `received-routes` omitting policy-denied EVPN routes (unlike
  v4); a landmine for the planned EVPN soft-in (which doesn't exist yet).
- **Display-only:** `route.rs:1762` `best_reason` records the last comparison's
  reason, not the deciding one, for prefixes with ≥3 paths (selection is correct);
  `show.rs:6871` `afi_safi_config_name` has no MUP arm → renders "unknown" and
  collapses both MUP families to one JSON key.
- **Plausible (not fully confirmed):** `route.rs:4917` VPNv6 AddPath
  advertisements never record `adj_out.v6vpn` → `show bgp summary` PfxSnt
  undercounts and sync-recorded rows go stale (the claimed withdraw-skip cannot
  fire today).

---

## Cleanup (verified; correctness outranks these)

### Duplication that has already caused divergence

- **Four copy-pasted Loc-RIB exact-match tables — `route.rs:1963`** (EVPN, MUP,
  Flowspec, BGP-LS): ~95 lines each, byte-identical except the key type, and **all
  four lack the `nexthop_reachable` withdraw gate** the generic `LocalRibTable` has
  (`1777`). Any future best-path fix must be applied five times.
- **`retag_vrf_exports_v4/v6` — `inst.rs:3248`** and **VRF import twins —
  `vrf/inst.rs:1281`**: ~100- and ~445-line hand-mirrored pairs whose own doc
  comments record past v4-only-fix bugs; the Inter-AS Option-AB hook is duplicated
  four times.
- **`inbound_attr_checks` re-inlined in 8 ingest paths — `route.rs:3427`**
  (v6, labelv4/v6, EVPN, MUP, flowspec, SR-policy, BGP-LS): the 4-check inbound
  block (AS-loop, enforce-first-as, ORIGINATOR_ID, CLUSTER_LIST) is copy-pasted
  instead of calling the existing helper.
- **Labeled v4/v6 update+withdraw twins — `route.rs:6621`** (~330 lines, docs say
  "See route_labelv4_*").

### Other reuse / simplification

- `BgpTop` hand-built at 44 sites (`peer.rs:1610`); helper `nht_install_top` exists.
- `show_bgp_vpnv6_table` (`show.rs:1163`) is a verbatim copy of the vpnv4 renderer;
  a `<P: Display>` generic pattern already exists in the same file.
- Duplicated helpers: `mup_direct_segment_id` (`vrf/inst.rs:536` = `show.rs:4492`,
  both raw magic numbers vs `ExtCommunityValue::as_mup`); `bgp_nexthop_to_ipaddr`
  (`route.rs:11615` = `8190`); `peer_has_negotiated` (`show.rs:208` =
  `Peer::is_afi_safi`); a 4th uptime formatter (`show.rs:2938`).
- Dead code: `PeerStat`/`PeerStatEntry` (`peer.rs:752`, never instantiated),
  `count_clear` (`1245`), `capability_as4` (`1965`) — all zero callers.

### Efficiency (hot paths)

- Per-prefix full-attribute deep-clones on ingest even under default-permit
  (`dispatch.rs:381`, `route.rs:3538`) — carry `Arc<BgpAttr>` in the shard message
  and clone only when a bound policy will rewrite.
- Unbatched per-prefix withdraw packets (`route.rs:5505`) — ~100× the packet count
  on a full-table withdraw sweep; batch withdrawn NLRIs per peer like the announce
  path.
- Legacy whole-table session-up dump inline on the main loop by default
  (`route.rs:13655`); the bounded-chunk cursor exists behind an unset env var.
- `sync_ctx` rebuilt per-route in dumps (`route.rs:13058`); `mem::replace` wins in
  all five `AdjRibTable::add` (`adj_rib.rs:53`); `worth_parallel` misses the
  group-task gate so precomputed memos are discarded (`route.rs:3990`, fix: add
  `&& !egress_group_task_enabled()`).

---

## Refuted (recorded so they aren't re-investigated)

- **`inst.rs:2755` / `inst.rs:2674`** — the `show`/tab-completion channel `unwrap`s
  do **not** panic on vty disconnect: the receivers are held by detached forwarding
  tasks / a single-branch `select!` and stay alive across the single-shot send.
- **`route.rs:9334`** — the BSID activation-edge resync is **not** broken at N>1:
  `mirror_v4_delta` maintains a main-shard `v4.1` winners replica the resync sweeps.
