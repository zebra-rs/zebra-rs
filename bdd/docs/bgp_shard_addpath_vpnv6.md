# BGP VPNv6 AddPath session-up sync at N>1 (all paths sync; per-path withdraw + peer-down)

## Overview

AddPath variant of @bgp_shard_sync_vpnv6, and the VPNv6 twin of the
vpnv4 AddPath test. Two PEs (z1, z2) export the SAME VPNv6 NLRI
(RD 65001:100, 2001:db8:9::/64) with different AS_PATHs (export-only
RT, so neither re-imports the other), so the sharded relay z3 holds
two candidates and AddPath-Sends both to the late peer z4. Pins that
`route_sync_vpnv6` dumps every candidate and registers each path-id in
`adj_out`, so a per-path config-withdraw on z1 (driven through the VRF
self-network withdraw path) and a peer-down (z2) remove only the right
path-id from a synced AddPath VPNv6 peer.

## Test Topology

```
  z1 (AS65001) PE ┐                            z1 path: "65003 65001"
                  ├─ z3 (AS65003, 4 shards) ── z4 (AS65004) AddPath-recv (late)
  z2 (AS65002) PE ┘  VPNv6 relay, no VRF       z2 path: "65003 65002"
```

## Notes

z1 and z2 each export RD 65001:100 / 2001:db8:9::/64. All four on bridge br0.

## Test Scenarios

| Scenario | Result |
|----------|--------|
| z1, z2 (PEs) and the sharded relay z3 come up; z3 holds two candidates | |
| the late AddPath peer z4 gets BOTH paths on sync | |
| z1 withdraws; only z1's path-id is withdrawn from the synced z4 | |
| z2's session drops; the surviving path is withdrawn from z4 too | |
| Teardown topology | |
