# BGP multiprotocol IPv6-unicast / MP_REACH follow-ups

Snapshot of remaining work as of `main` ≈ commit `7b8c24e3` (PR #1286
merged). This series made plain IPv6 unicast work end to end and
un-dropped every MP_REACH family on receive; the items below are the
gaps that were deliberately left out of those small PRs.

Updated 2026-07-21 with the IPv4-unicast arc (#2045 / #2051 / #2053) —
see that section for what landed and its two remaining follow-ups. Two
older items are annotated resolved/stale in place rather than deleted,
so the reasoning behind them stays readable.

Standing guidance still applies: recommend the smallest meaningful
slice with its main tradeoff, let the user redirect, ship one branch /
one PR at a time.

## Recently landed (context)

- **#1284** — new `show bgp [ipv4|ipv6] [<addr>|<prefix> [longer-prefix]]`
  command tree, with the keyword-less IPv4 shortcut via the
  `ext:default-child` matcher feature (`show bgp 10.0.0.1` ==
  `show bgp ipv4 10.0.0.1`).
- **#1285** — plain IPv6 unicast (SAFI 1) end to end: origination
  (`route_add_v6`/`route_del_v6` + the `(Ip6,Unicast)` arm in
  `config_network`), advertise-on-establish (`route_sync_ipv6` +
  `send_ipv6_direct` + `send_eor_ipv6_unicast`, wired into
  `route_sync`), and receive (surface `MpReachAttr::Ipv6` +
  accept a 16- or 32-octet RFC 2545 next-hop in the decoder).
  Validated zebra-rs↔zebra-rs through to kernel FIB install.
- **#1286** — surface *all* remaining MP_REACH families on receive.
  The attribute parser's `MpReachNlri` match dropped everything but
  Vpnv4/Evpn/Ipv4/Ipv6 into `_ => {}`; now `other => mp_update = Some`
  surfaces VPNv6, IPv4/IPv6 Labeled-Unicast, Flowspec, SR-Policy,
  RTC (v4/v6), BGP-LS, MUP for dispatch by `route_from_peer`.

## 2026-07-21: IPv4 unicast over the MP attributes (#2045 / #2051 / #2053)

A later arc closed the AFI=1/SAFI=1 half of this story. RFC 4760 lets a
speaker carry plain IPv4 unicast in the MP attributes instead of the
UPDATE's legacy NLRI / Withdrawn Routes fields, and xk6-bgp and other
MP-first stacks do exactly that. Both directions were broken, in
opposite ways:

- **#2045** (MP_REACH, §3, external contribution) — the
  `MpReachAttr::Ipv4` arm in `route_from_peer` only matched the RFC 8950
  IPv4-over-IPv6 shape and warned-and-dropped everything else. An UPDATE
  with a v4 next-hop inside MP_REACH was accepted with no error and no
  effect: no Loc-RIB entry, no FIB install, no re-advertisement. Fixed by
  splitting the arm on next-hop family and stamping the MP_REACH next-hop
  (which supersedes any NEXT_HOP attribute) before the normal
  `route_ipv4_update_batch` path.
- **#2053** (MP_UNREACH, §4) — `MpUnreachAttr` had *no* AFI=1/SAFI=1 arm,
  only a never-constructed `Ipv4Eor` stub, so the withdrawal fell through
  to the trailing `Err` in `parse_nlri_opt`. That error is on neither the
  RFC 7606 treat-as-withdraw nor the attribute-discard list, so the whole
  UPDATE failed to parse and `peer_packet_parse` dropped the connection —
  **a session reset, not a failed withdrawal**. #2045 is what made this
  reachable: a peer that announces via MP_REACH withdraws the same way,
  so the first withdrawal killed a session that was carrying routes fine.

**The parsers are now symmetric.** MP_REACH and MP_UNREACH cover the same
13 AFI/SAFI combinations, so there is no remaining family where a peer
can announce successfully and then reset the session by withdrawing.
Re-run that comparison (the `if header.afi == …` arms in `mp_reach.rs`
vs `mp_unreach.rs`) whenever a family is added to one side.

**#2051 added a scripted-speaker BDD harness**, which is relevant to the
interop item below: `bdd/tests/scripts/bgp_mp_reach_send.py` is a
stdlib-only Python BGP speaker driven by trigger files
(`.announce` / `.withdraw_traditional` / `.withdraw_mp`), used by feature
`bgp_mp_reach_ipv4`. It exists because a gobgp/FRR harness *cannot* cover
these encodings — no mainstream implementation emits them. Reach for it
for any "only a weird sender produces this" case (malformed attributes,
unusual next-hop lengths); reach for gobgp/FRR for ordinary families.

Two traps that cost time and are worth reusing:

- The DUT neighbor facing the script must set
  `transport: {passive-mode: true}`. The script never listens on 179, so
  the DUT's dial-outs get refused and it cycles Idle → Connect → Idle,
  and **Idle refuses inbound connections** — the script's connect is
  RST'd forever.
- When the failure mode is a session reset, assert the session is still
  Established. The route-removal assertions pass either way, because a
  reset drops the peer's routes too; without the session assertion the
  MP_UNREACH scenario goes green against the broken build.

### Follow-ups from that arc

Neither is urgent; both are latent rather than user-visible today.

**`MpUnreachAttr::Rtcv4` / `Rtcv6` have no `attr_emit` arm.** They fall
through the `_ => {}` catch-all and encode *nothing*. Unreachable right
now — zebra-rs only ever constructs the `Rtcv4Eor` / `Rtcv6Eor` forms on
send, and those do have arms — so nothing is broken. It is a trap for
whoever first implements RTC membership *withdrawal*, because it fails
silently rather than loudly. This is the same latent shape #2053 fixed
for `Ipv4Eor`, which had likewise been encoding nothing.

**The canonical IPv4-unicast end-of-RIB is not detected on receive.**
RFC 4724 §2 makes the bare empty UPDATE the v4 EoR, but `route_from_peer`
has no empty-UPDATE check, so only the unusual empty-MP_UNREACH form
(the `Ipv4Eor` arm #2053 added) fires the v4 stale timer. Impact is
bounded: `start_stale_timer` still flushes on timeout, so a restarting
peer's stale routes linger until it expires instead of clearing promptly
on EoR. It is a graceful-restart conformance gap, not a correctness bug.
Worth its own change rather than a tack-on, because the fix has to
separate a genuine EoR from a merely malformed empty UPDATE.

## The big one: per-family end-to-end interop validation

#1286 is a *parse-layer enabler* — it routes each family to its
existing `route_from_peer` handler, but those handlers were written
control-plane-first and several have **never processed a real
on-the-wire UPDATE**. A latent handler bug (an `.expect()` / index
panic on attacker- or peer-shaped data) that used to be masked by the
silent drop will now surface.

Highest payoff per line: a **gobgp (or FRR) peer harness** under
`bdd/` that advertises one route per family into zebra-rs and asserts
it lands in the right Loc-RIB / `show` output. The `@bgp_gobgpd_*`
features already wire gobgp into a netns, so the scaffolding exists.
Priority order roughly matches real-world use: VPNv6, IPv6/IPv4
labeled-unicast, then Flowspec / SR-Policy / RTC / BGP-LS.

The original report that kicked off this series was **FRR advertising
IPv6 unicast routes (32-octet next-hop + an SRv6 `Local SID`
Prefix-SID) that zebra-rs dropped**. The 32-octet decode and the Ipv6
dispatch are fixed and unit-tested, but the live FRR+SRv6 path has not
been re-confirmed against the reporter's topology — do that first.

## Small / one-PR each

### `show bgp neighbor <X> advertised-routes` for IPv6 unicast
`route_sync_ipv6` intentionally skips Adj-RIB-Out: `AdjRib<Out>` has
no `add_v6` (only `AdjRib<In>` does), and the event-driven
`route_advertise_to_peers_v6` skips it too. Consequence: v6-unicast
routes we advertise are invisible to `advertised-routes`, and a future
soft-reconfig-out can't sweep them. Add a v6 table to `AdjRib<Out>` +
the `add_v6`/`remove_v6` methods + register in `route_sync_ipv6` and
`route_advertise_to_peers_v6`, then surface in the show handler.

### Encode the 32-octet (global ‖ link-local) v6 next-hop
`ipv6_attr_emit` always writes the 16-octet global-only form. RFC 2545
§3 recommends including the link-local on a shared link, and some
stacks expect it. Receive already accepts both (#1285). Consider
emitting the 32-octet form when the egress interface has a link-local
(mirrors what FRR does), so direct-connect v6 forwarding has the
link-local available.

### Use the received link-local from the 32-octet next-hop
The v6-unicast MP_REACH decoder parses the 32-octet form but discards
the link-local (uses only the global). For a directly-connected eBGP
peer the link-local is the correct forwarding next-hop; today we lean
on the global + ND. Capture it when v6 next-hop resolution needs it.

## Medium

### `route_sync_*` for the other advertise-on-establish families
`route_sync` now dumps IPv4/IPv6 unicast, VPNv4, EVPN and SR-Policy on
session establish, but **VPNv6 is event-driven only** (no
`route_sync_vpnv6`, per the RTC series note) and **labeled-unicast
(v4/v6) has no `route_sync_label*`**. A peer that establishes *after*
those routes already exist in the Loc-RIB never gets the initial dump
— the same gap #1285 fixed for plain v6 unicast. Mirror
`route_sync_ipv6` for each: `route_sync_vpnv6`, `route_sync_labelv4`,
`route_sync_labelv6`, with their EoR markers, gated on the negotiated
AFI/SAFI. (RTC membership is already sent on establish; VPNv6 advertise
is additionally gated on the peer's RTCv6 EoR — preserve that.)

### RFC 7606 treat-as-withdraw coverage for the newly-surfaced families
**Resolved — verified 2026-07-21.** `withdraw_mp_reach` now has a branch
for all ten families that can carry a Prefix-SID (Vpnv4, Vpnv6, Evpn,
Ipv4, Ipv6, Labelv4, Labelv6, Flowspec, SrPolicy, LinkState). RTC falls
into the `_ =>` catch-all deliberately — it cannot carry a Prefix-SID
attribute, so there is nothing to withdraw. Original concern below.

When `treat_as_withdraw` is set, `route_from_peer` calls
`withdraw_mp_reach`. Confirm it has a branch for every family #1286
now surfaces (VPNv6 / labeled / Flowspec / SR-Policy / RTC / BGP-LS)
rather than silently leaving an installed copy when a malformed
attribute rides along — otherwise a malformed-attr UPDATE leaks the
reachable NLRI it should withdraw.

## Known gaps / not blocking

- ~~**MUP** is surfaced by #1286 but `route_from_peer` has no MUP arm.~~
  **Stale — verified 2026-07-21.** `route_from_peer` has a
  `MpReachAttr::Mup` arm that stamps the MP_REACH next-hop and calls
  `route_mup_update`; the MUP series built out receive, Loc-RIB and
  dataplane since this was written (see `bgp-mup-followups.md`).
- The explicit `MpReachAttr::Ipv4` / `Ipv6` arms in the attribute
  parser are now redundant with the `other =>` catch-all (they only
  set `mp_update`, same as the default). `Vpnv4` / `Evpn` still stamp
  `bgp_attr.nexthop` so they must stay; Ipv4/Ipv6 could fold into the
  default in a cleanup pass, but the explicit arms document intent —
  leave unless churning the file for another reason.

## Cross-references

- `bgp-labeled-unicast.md` — SAFI 4 control-plane state; its Phase 5
  dataplane was control-plane-green but not real-run-validated, which
  the interop harness above would also cover.
- `bgp-prefix-sid-rfc9252.md` — SRv6 L3 Service TLV / Prefix-SID codec
  (relevant to the FRR `Local SID` interop case).
- `bgp-flowspec-plan.md`, `bgp-sr-policy-plan.md`,
  `bgp-link-state-plan.md` — the per-family receive handlers #1286
  unblocked; each plan's "receive" milestone is now wire-reachable and
  wants the interop validation.
