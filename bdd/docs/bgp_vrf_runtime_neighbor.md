# Per-VRF BGP neighbors applied to a running VRF at runtime

## Overview

As an operator of an L3VPN PE
I want to add, reconfigure, and remove a `router bgp vrf <name>`
neighbor on a VRF that is already running
So that a customer-edge change takes effect on the live task without
respawning it — CE1 keeps its session while CE2 is added, given BFD,
and removed.

Regression guard for the incremental per-VRF neighbor path (PR #2087)
and its two follow-ups: TCP-AO re-subscribe on reconfigure (#2094) and
live BFD for runtime-added neighbors (#2095). Before #2087 a neighbor
edit either did nothing until the next respawn or reset every session
in the VRF; these scenarios prove the edit is surgical.

The whole point is that CE1's session must NOT flap while CE2 is
churned: `runtime_structure_eq` keeps a neighbor-only edit off the
respawn path, so CE1 is the "still Established" witness. CE2's BFD
session appearing in `show bfd peers` after enable and disappearing
after the neighbor delete guards the `AddPeer` BFD subscribe and the
`remove_peer` / `UnsubscribeClient` teardown (a leaked session would
linger).

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

Both PE-CE interfaces are enslaved to vrf-cust from the start; only
the BGP neighbor for CE2 is deferred and driven in at runtime with
`vtyctl apply -c`.

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Build the runtime-neighbor VRF topology | |
| Adding a neighbor at runtime brings it up without disturbing CE1 | |
| Enabling BFD on a live neighbor subscribes a session | |
| Removing a neighbor at runtime tears down its session, route, and BFD | |
| Teardown topology | |
