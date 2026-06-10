# Clearing BGP Sessions

BGP exposes FRR/IOS-XR-style operational `clear` commands that act on
the running instance without touching the configuration. They live
under the `clear bgp …` tree and take effect immediately — there is no
`commit`.

```
clear bgp <ipv4|ipv6|vpnv4|evpn> <peer-address|all> [soft [in|out]]
```

The peer can be typed straight after the AFI (the FRR spelling), or
behind an explicit `neighbor` keyword — both resolve to the same
command:

```
zebra# clear bgp ipv4 192.168.0.2
zebra# clear bgp ipv4 neighbor 192.168.0.2      # same thing
zebra# clear bgp ipv4 all soft out
```

`all` targets every established peer that negotiated the given
AFI/SAFI.

## Hard clear — bounce the session

```
clear bgp ipv4 192.168.0.2
```

Without `soft`, the clear is a **hard reset**: the TCP session is torn
down, the peer's routes are withdrawn, and the FSM reconnects from
scratch. On a healthy directly-connected session the cycle is quick —
re-Established within a few seconds, followed by a full table resync —
but it *is* disruptive: routes from the peer disappear until the
session is back.

Use it when session-level state must be renegotiated: capability
changes, authentication/TTL changes (see
[TTL Security](ch-02-11-bgp-ttl-security.md), whose runtime enablement
relies on exactly this), or a session that is visibly wedged.

## Soft clear — re-evaluate without bouncing

```
clear bgp ipv4 192.168.0.2 soft          # both directions
clear bgp ipv4 192.168.0.2 soft in       # inbound only
clear bgp ipv4 192.168.0.2 soft out      # outbound only
```

Soft clears re-run policy without touching the TCP session:

- **`soft in`** replays the peer's stored Adj-RIB-In through the
  current inbound policy. zebra-rs always stores received routes
  pre-policy (soft-reconfiguration inbound is effectively always on),
  so no Route Refresh round-trip is needed: routes the new policy
  denies are withdrawn from the Loc-RIB, routes it now permits are
  (re-)installed.
- **`soft out`** re-runs the egress transform and outbound policy over
  the Loc-RIB and re-advertises toward the peer, withdrawing anything
  the peer previously received that the current policy no longer
  permits. This is the "force a re-flood" tool after an outbound
  policy or attribute change.
- **`soft`** does both, inbound first.

EVPN `soft in` is not implemented yet; the command reports
`%% EVPN soft-in is not yet implemented` and leaves the session alone.

Note that a `soft in` is rarely *needed* after a config change:
editing an inbound policy already triggers the same re-evaluation
automatically. The explicit command exists for operational use —
re-checking the table after out-of-band changes, or confirming what
the current policy admits.

## Where the per-AFI forms apply

The AFI token selects which negotiated family the clear targets:
`ipv4` and `ipv6` cover the unicast tables, `vpnv4` the
BGP/MPLS-VPN table of an L3VPN PE or ASBR, and `evpn` the L2VPN EVPN
table. A hard clear always bounces the whole session (BGP sessions are
per-peer, not per-AFI); the soft forms re-evaluate just the selected
family.
