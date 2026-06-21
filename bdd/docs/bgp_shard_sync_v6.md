# BGP IPv6-unicast read paths at N>1 (sync / show stay correct — v6 is not pooled)

## Overview

The IPv6 counterpart of @bgp_shard_v4_sync, asserting the *absence* of
the read-path bug for v6. At ZEBRA_BGP_SHARDS>1 only plain v4-unicast is
dispatched to the worker pool; IPv6-unicast is sync-ingested straight to
the main `bgp.shard` (no `RouteBatchV6`). So `bgp.shard.v6` stays
populated at N>1, and the synchronous main-task read paths —
`route_sync_ipv6` (session-up dump) and `show bgp ipv6` — see the routes
with no mirror needed. This feature pins that: a late-establishing v6
peer must still get the full table on sync, and the sharded node must
show its own v6 RIB. (v4 needed `BgpShard::mirror_v4` for this; v6 does
not, and this guards against v6 ever regressing into the same hole.)
z2 is the sharded device under test (4 shards) and the transit between
z1 (origin) and two downstream peers:

## Test Topology

```
                            ┌── z3 (AS65003)  early peer  → event-driven (control)
  z1 (AS65001) ── z2 (AS65002, 4 shards) ──┤
   2001:db8::1/64  2001:db8::2/64          └── z4 (AS65004)  late peer   → sync
   origin          sharded transit
```

## Notes

All four on bridge br0. z1 originates 2001:db8:a::1/128 + 2001:db8:a::2/128.

## Test Scenarios

| Scenario | Result |
|----------|--------|
| z1, the sharded z2, and the early peer z3 come up (no routes yet) | |
| control — z1 originates while z3 is up; the event-driven advertise reaches z3 | |
| the late peer z4 gets the routes on sync, and z2 can show its own RIB | |
| z1 withdraws one route; z2's sync shard drops it | |
| z1's session drops; the peer-down sweep clears its routes | |
| Teardown topology | |
