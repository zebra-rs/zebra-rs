# A route a late peer learned at session-up is withdrawn through the per-peer egress task

## Overview

As a network operator running the per-peer egress task
(router bgp sharding peer-sharding true)
I want a neighbor that came up after a route was learned to lose that
route when it is withdrawn
So no neighbor keeps forwarding to us on a route we no longer have.

A neighbor that comes up is sent the routes already held (the session-up
dump). With the per-peer egress task and no RIB sharding (N=1), the dump
was never recorded in the task's Adj-RIB-Out; the task sends a withdraw
only for a route it recorded, so every route the neighbor learned from
the dump stayed with it, and `advertised-routes` did not list them. The
task serves IPv4 unicast only, so there is no IPv6 twin.

## Test Topology

```
                                ┌── z3 (AS65003)  early peer
  z1 (AS65001) ── z2 (AS65002) ─┤
   origin         peer-sharding └── z4 (AS65004)  late peer
                  true (N=1)
```

## Notes

All four on bridge br0 10.0.25.0/24. z1 originates 10.25.10.0/24 and
10.25.11.0/24 after z3 is up (z3 learns them event-driven, the control)
and before z4 is (z4 learns them from the dump).

## Config Files

- z1-base.yaml: eBGP to z2, no routes. z1-routes.yaml: the two routes.
- z2.yaml: DUT — peer-sharding true, rib-sharding unset; eBGP to z1, z3, z4.
- z3.yaml, z4.yaml: eBGP to z2.

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Setup; z2 runs the per-peer egress task and z3 establishes | |
| z1's routes reach the early peer event-driven | |
| The late peer learns the routes from the session-up dump | |
| z1 withdraws the routes; both peers lose them | |
| Teardown topology | |
