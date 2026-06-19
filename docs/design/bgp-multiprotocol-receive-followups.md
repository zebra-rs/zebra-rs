# BGP multiprotocol IPv6-unicast / MP_REACH follow-ups

Snapshot of remaining work as of `main` ≈ commit `7b8c24e3` (PR #1286
merged). This series made plain IPv6 unicast work end to end and
un-dropped every MP_REACH family on receive; the items below are the
gaps that were deliberately left out of those small PRs.

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
When `treat_as_withdraw` is set, `route_from_peer` calls
`withdraw_mp_reach`. Confirm it has a branch for every family #1286
now surfaces (VPNv6 / labeled / Flowspec / SR-Policy / RTC / BGP-LS)
rather than silently leaving an installed copy when a malformed
attribute rides along — otherwise a malformed-attr UPDATE leaks the
reachable NLRI it should withdraw.

## Known gaps / not blocking

- **MUP** is surfaced by #1286 but `route_from_peer` has no MUP arm
  (falls into its own harmless `_ => {}`). If MUP receive is ever
  wanted, add the handler + Loc-RIB; until then it's parsed and
  ignored (no worse than before).
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
