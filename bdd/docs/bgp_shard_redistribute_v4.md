# BGP IPv4 redistribution under RIB sharding (N>1)

## Overview

At N>1 the worker pool owns the IPv4-unicast Loc-RIB, and main's shard is
only its read replica. A redistributed IPv4 route was written to the
replica, as `network` was before it was moved onto the pool. The pool's
session-up dump never had it, so a neighbor that established after the
route was redistributed never learned it. And the pool's best-path never
saw it, so a peer's path for the same prefix won, despite the
redistributed route's weight of 32768.

Now `route_redist_inject` and `route_redist_withdraw` dispatch an
`OriginateV4` to the pool shard that owns the prefix, carrying the
source's path-id and the metric as MED, as `route_add` and `route_del`
do.

z1 is the sharded device under test (4 shards). It redistributes three
static routes before either neighbor is configured, so z2 and z3 can only
learn them from the session-up dump. z3 also originates 10.50.1.0/24.

## Test Topology

```
  z2 (AS65002) ── z1 (AS65001, 4 shards) ── z3 (AS65003)
   10.0.0.2/24    10.0.0.1/24                10.0.0.3/24
                  redistributes static       originates 10.50.1.0/24
                  10.50.1.0/24
                  10.50.2.0/24
                  10.50.3.0/24
```

## Notes

All three on bridge br0.

## Test Scenarios

| Scenario | Result |
|----------|--------|
| z1 redistributes before its neighbors come up | |
| a neighbor that came up later learns the redistributed routes | |
| the redistributed route stays best over z3's path for the same prefix | |
| removing static routes withdraws their redistributed routes | |
| Teardown topology | |
