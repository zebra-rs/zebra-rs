# BGP IPv4-unicast AddPath session-up sync at N>1 (all paths sync; per-path withdraw + peer-down)

## Overview

AddPath variant of @bgp_shard_v4_sync. Two origins (z1, z2) advertise the
same prefix, so the sharded z3 holds two candidates; z3 AddPath-Sends both
to the late peer z4. This exercises the AddPath dimension of the N>1 sync
fixes: the read-replica mirror must carry the candidate table (`v4.0`,
not just best), and `route_sync_ipv4` must dump every candidate and
register each in `adj_out` so a later per-path withdraw / peer-down
removes only that path-id from z4.

## Test Topology

```
  z1 (AS65001) ┐                        z1 path: "65003 65001"
               ├─ z3 (AS65003, 4 shards) ── z4 (AS65004) AddPath-recv (late)
  z2 (AS65002) ┘  AddPath-send to z4      z2 path: "65003 65002"
```

## Notes

z1 and z2 each originate 10.10.10.0/24. All four on bridge br0 (192.168.0.x).

## Test Scenarios

| Scenario | Result |
|----------|--------|
| z1, z2 and the sharded z3 come up; z3 holds two candidates | |
| the late AddPath peer z4 gets BOTH paths on sync | |
| z1 withdraws; only z1's path-id is withdrawn from the synced z4 | |
| z2's session drops; the surviving path is withdrawn from z4 too | |
| Teardown topology | |
