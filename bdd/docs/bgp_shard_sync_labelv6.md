# BGP labeled-unicast (v6) session-up sync at N>1 (sync + withdraw reach a late peer)

## Overview

The IPv6 labeled-unicast counterpart of @bgp_shard_sync_lu, exercising
`route_sync_labelv6`. At ZEBRA_BGP_SHARDS>1 labeled-unicast is
sync-ingested to the main `bgp.shard` (not pooled), so `bgp.shard.v6lu`
stays populated and the read paths work. The risk this pins is the
Adj-RIB-Out one v6/LU-v4 exposed: `route_sync_labelv6` dumps the LU-v6
Loc-RIB to a newly-established peer and must register each prefix in
`adj_out.v6lu`, otherwise the event-driven LU withdraw's gate skips that
peer and the route gets stuck. (This is native LU-v6 over an IPv6
session; the next-hop-self is the v6 session local address.)
z2 is the sharded device under test (4 shards) and transit between
z1 (origin) and two downstream peers:
`show bgp labeled-unicast` renders both the v4lu and v6lu Loc-RIBs, so
the v6 LU prefixes appear there.

## Test Topology

```
                            ┌── z3 (AS65003)  early peer  → event-driven (control)
  z1 (AS65001) ── z2 (AS65002, 4 shards) ──┤
   2001:db8::1/64  2001:db8::2/64          └── z4 (AS65004)  late peer  → sync
   origin          sharded transit
```

## Notes

All four on bridge br0. z1 originates LU-v6 2001:db8:a::1/128 + ::2/128.

## Test Scenarios

| Scenario | Result |
|----------|--------|
| z1, the sharded z2, and the early peer z3 come up (no routes yet) | |
| control — z1 originates while z3 is up; the event-driven advertise reaches z3 | |
| the late peer z4 gets the routes on sync, and z2 can show its own RIB | |
| z1 withdraws one route; the withdraw reaches the synced peer z4 | |
| z1's session drops; the peer-down sweep clears its routes from z4 | |
| Teardown topology | |
