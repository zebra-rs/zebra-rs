# A neighbor that comes up waits for the forwarding plane under RIB sharding

## Overview

As a network operator running suppress-fib-pending with RIB sharding
(router bgp sharding rib-sharding > 1)
I want a neighbor that comes up while a prefix awaits the forwarding
plane's ack to learn that prefix only once the ack, or the deadline,
releases it
So no neighbor is told about a route we may not forward yet.

With suppress-fib-pending a prefix's advertisement waits for the
forwarding plane to confirm the install. The session-up dumps on main
skip a held prefix and leave it to the release; with RIB sharding the
IPv4-unicast dump runs in the shard pool instead, which had no such gate,
so a neighbor that came up learned the held prefix at once (review
finding #30). Nothing here acknowledges installs (no FPM), so every hold
runs to its 30-second deadline: that window is the test. IPv4 only — the
pool serves plain IPv4 unicast; the IPv6 session-up dump runs on main.

## Test Topology

```
  z2 (AS65002) ── z1 (AS65001) ── z3 (AS65003)
   origin          DUT:            late peer
                   rib-sharding 2,
                   suppress-fib-pending
```

## Notes

All three on bridge br0 10.0.30.0/24. z2 originates 10.30.10.0/24 once
z1 is up with it; z3 comes up while z1 still holds it.

## Config Files

- z1.yaml: DUT — rib-sharding 2, suppress-fib-pending; eBGP to z2, z3.
- z2-base.yaml: eBGP to z1, no routes. z2-route.yaml: the route.
- z3.yaml: eBGP to z1.

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Setup; z1 shards its RIB and z2 establishes | |
| z1 holds z2's route for the forwarding plane | |
| The late peer's session-up dump holds the route back | |
| The deadline releases the route to the late peer | |
| Teardown topology | |
