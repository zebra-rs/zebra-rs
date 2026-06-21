# BGP IPv4-unicast read paths at N>1 (show / session-up sync read the empty main shard)

## Overview

Regression test for a correctness gap in BGP RIB sharding. At
ZEBRA_BGP_SHARDS>1, plain IPv4-unicast routes are dispatched to the
worker-shard pool (RouteBatchV4) and live ONLY in the pool shards; the
reduce (`route_apply_bestpath_v4_batch`) used to do FIB-install +
advertise but never mirror the best-path back into the synchronous
`bgp.shard`, so every read path that consults `bgp.shard.v4` was empty
at N>1:
Forwarding itself is unaffected: the event-driven advertise runs off the
best-path delta, not `bgp.shard`. This is IPv4-unicast-specific (the only
pooled family); v6 / VPNv4 / VPNv6 / labeled-unicast are sync-ingested,
so their `bgp.shard` tables stay populated and read correctly at N>1.
z2 is the sharded device under test (4 shards) and the transit between
z1 (origin) and two downstream peers:
FIXED by the read-replica mirror: the pool reduce
(`route_apply_bestpath_v4_batch` → `BgpShard::mirror_v4`) now keeps the
main shard's `bgp.shard.v4` in step with the pool-owned table, so both
read paths — `route_sync_ipv4` (for the late peer z4) and `show bgp
ipv4` (z2's own RIB) — see the routes at N>1. This feature now guards
against regressing that. (The sync build still runs serially on the
main task; parallelizing its egress is a separate optimization, see
docs/design/bgp-rib-sharding-plan.md §B.4.)
A THIRD read path — `show bgp neighbor <peer> received-routes` (the
peer's Adj-RIB-In) — is NOT covered by the Loc-RIB mirror: the
authoritative adj_in lives in the pool shards, so at N>1 this read
scatter-gathers it from every shard (A2 ⑤, `ShardMsg::DumpAdjInV4`). The
received-routes scenario below guards that.

## Test Topology

```
                         ┌── z3 (AS65003)  early peer  → event-driven (control)
  z1 (AS65001) ── z2 (AS65002, 4 shards) ──┤
   10.0.0.1/24    10.0.0.2/24              └── z4 (AS65004)  late peer   → sync (bug)
   origin         sharded transit
```

## Notes

All four on bridge br0. z1 originates 10.10.10.0/24 + 10.10.11.0/24.

## Test Scenarios

| Scenario | Result |
|----------|--------|
| z1, the sharded z2, and the early peer z3 come up (no routes yet) | |
| control — z1 originates while z3 is up; the event-driven advertise reaches z3 | |
| the late peer z4 gets the routes on sync, and z2 can show its own RIB | |
| z2's received-routes from z1 are gathered from the pool shards (N>1 Adj-RIB-In) | |
| z1 withdraws one route; the sharded reduce removes it from z2's mirror | |
| z1's session drops; the sharded peer-down sweep clears z2's mirror | |
| Teardown topology | |
