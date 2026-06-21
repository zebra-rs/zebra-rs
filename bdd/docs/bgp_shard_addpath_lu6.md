# BGP labeled-unicast (v6) AddPath session-up sync at N>1 (all paths sync; per-path withdraw + peer-down)

## Overview

AddPath variant of @bgp_shard_sync_labelv6. Two origins (z1, z2) advertise the
same LU-v6 prefix, so the sharded z3 holds two candidates and AddPath-Sends
both to the late peer z4. Pins that `route_sync_labelv6` dumps every
candidate from `bgp.shard.v6lu.0` and registers each path-id in
`adj_out.v6lu`, so a per-path withdraw + peer-down remove only the right
path-id from a synced AddPath LU peer. `show bgp labeled-unicast`
carries the AS_PATH column.

## Test Topology

```
  z1 (AS65001) ┐                        z1 path: "65003 65001"
               ├─ z3 (AS65003, 4 shards) ── z4 (AS65004) AddPath-recv (late)
  z2 (AS65002) ┘  AddPath-send to z4      z2 path: "65003 65002"
```

## Notes

z1 and z2 each originate LU 2001:db8:beef::/64. All four on bridge br0.

## Test Scenarios

| Scenario | Result |
|----------|--------|
| z1, z2 and the sharded z3 come up; z3 holds two candidates | |
| the late AddPath peer z4 gets BOTH paths on sync | |
| z1 withdraws; only z1's path-id is withdrawn from the synced z4 | |
| z2's session drops; the surviving path is withdrawn from z4 too | |
| Teardown topology | |
