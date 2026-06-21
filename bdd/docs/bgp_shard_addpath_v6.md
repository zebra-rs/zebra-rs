# BGP IPv6-unicast AddPath session-up sync at N>1 (all paths sync; per-path withdraw + peer-down)

## Overview

AddPath variant of @bgp_shard_sync_v6. Two origins (z1, z2) advertise the
same v6 prefix, so the sharded z3 holds two candidates and AddPath-Sends
both to the late peer z4. v6 is sync-ingested (not pooled), so this pins
that `route_sync_ipv6` dumps every candidate from `bgp.shard.v6.0` and
registers each path-id in `adj_out.v6`, so a per-path withdraw + peer-down
remove only the right path-id from a synced AddPath peer.

## Test Topology

```
  z1 (AS65001) ┐                        z1 path: "65003 65001"
               ├─ z3 (AS65003, 4 shards) ── z4 (AS65004) AddPath-recv (late)
  z2 (AS65002) ┘  AddPath-send to z4      z2 path: "65003 65002"
```

## Notes

z1 and z2 each originate 2001:db8:beef::/64. All four on bridge br0.

## Test Scenarios

| Scenario | Result |
|----------|--------|
| z1, z2 and the sharded z3 come up; z3 holds two candidates | |
| the late AddPath peer z4 gets BOTH paths on sync | |
| z1 withdraws; only z1's path-id is withdrawn from the synced z4 | |
| z2's session drops; the surviving path is withdrawn from z4 too | |
| Teardown topology | |
