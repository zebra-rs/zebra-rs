# Two BGP CE neighbors under a single VRF

## Overview

As a service provider attaching more than one customer edge to the
same VRF on a PE
I want every neighbor under `router bgp vrf <name>` to establish and
carry routes, not just the first one
So that a multi-CE VRF converges instead of silently wedging one
session in Idle.
Regression guard for issue #2077 / PR #2071. `materialize_peers`
used to call `Peer::start()` *before* `PeerMap::insert_with_key`
assigned the peer's stable ident. `start_timer!` captures
`peer.ident` by value when it arms the idle-hold timer, and the
per-VRF loop dispatches `Message::Event(ident, …)` purely on that
value, so every peer past the first armed its timer under ident 0
and its `Event::Start` was delivered to the *first* peer instead.
The wedged peer stays in Idle, which blocks the session from both
directions: it never dials, and `handle_peer_connection` drops
inbound streams for an Idle peer, so the CE's own dial is refused
too. Before the fix CE2 below never leaves Idle.
Every pre-existing BDD config puts at most one neighbor under a
`router bgp vrf` block (106 such blocks, zero with two), which is
why nothing caught this. The second neighbor is the entire point of
this topology.

## Test Topology

```
   ce1 ────────── pe1 ────────── ce2
   AS 65001    AS 65000        AS 65002
   lo          vrf-cust        lo
   10.0.1.1/32 RD 65000:1      10.0.2.1/32
        .2 ── .1        .1 ── .2
       10.1.0.0/30    10.2.0.0/30
```

## Notes

Both PE-CE sessions are eBGP and both live inside vrf-cust. There is
no VPNv4 core: PE1 re-advertises each CE's prefixes to the other CE
out of the same VRF Loc-RIB, so the CE-to-CE ping proves both
sessions carry routes rather than merely reaching Established.

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Build the dual-CE VRF topology | |
| Both PE-CE sessions in the VRF reach Established | |
| The VRF Loc-RIB holds both CE's prefixes | |
| CE-to-CE reachability across the shared VRF | |
| Teardown topology | |
