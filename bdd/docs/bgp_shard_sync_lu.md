# BGP labeled-unicast (v4) session-up sync at N>1 (sync + withdraw reach a late peer)

## Overview

The labeled-unicast counterpart of @bgp_shard_v4_sync / @bgp_shard_sync_v6.
At ZEBRA_BGP_SHARDS>1, labeled-unicast is sync-ingested to the main
`bgp.shard` (not pooled), so `bgp.shard.v4lu` stays populated and the
read paths work. The risk this pins is the Adj-RIB-Out one v6 exposed:
`route_sync_labelv4` dumps the LU Loc-RIB to a newly-established peer and
must register each prefix in `adj_out.v4lu`, otherwise the event-driven
LU withdraw's `adj_out.v4lu` gate skips that peer and the route gets
stuck. (route_sync_labelv6 carries the byte-identical fix.)
z2 is the sharded device under test (4 shards) and transit between
z1 (origin) and two downstream peers:

## Test Topology

```
                            ┌── z3 (AS65003)  early peer  → event-driven (control)
  z1 (AS65001) ── z2 (AS65002, 4 shards) ──┤
   192.168.0.1/24  192.168.0.2/24          └── z4 (AS65004)  late peer  → sync
   origin          sharded transit
```

## Notes

All four on bridge br0. z1 originates LU 10.10.10.1/32 + 10.10.10.2/32.

## Test Scenarios

| Scenario | Result |
|----------|--------|
| z1, the sharded z2, and the early peer z3 come up (no routes yet) | |
| control — z1 originates while z3 is up; the event-driven advertise reaches z3 | |
| the late peer z4 gets the routes on sync, and z2 can show its own RIB | |
| z1 withdraws one route; the withdraw reaches the synced peer z4 | |
| z1's session drops; the peer-down sweep clears its routes from z4 | |
| Teardown topology | |
