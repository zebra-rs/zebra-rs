# BGP VPNv6 session-up sync at N>1 (sync + withdraw + peer-down reach a late peer)

## Overview

VPNv6 counterpart of @bgp_shard_sync_vpnv4. VPNv6 is sync-ingested to
the main `bgp.shard` (not pooled), so its Loc-RIB stays populated at
N>1. This pins that `route_sync_vpnv6` dumps the VPNv6 Loc-RIB to a
late peer AND registers each route in `adj_out` (it already does), so
a later config-withdraw + peer-down reach the synced peer.
z1 is a PE: a route in vrf-blue (RD 65001:100, RT 65001:100) exported
to VPNv6. z2 (4 shards) is an eBGP VPNv6 relay (no VRF — holds the
VPNv6 routes and re-advertises, Inter-AS Option-B style). z3
establishes early (event-driven control); z4 establishes late
(session-up route_sync_vpnv6). All sessions ride IPv6 transport.

## Test Topology

```
                            ┌── z3 (AS65003)  early peer  → event-driven (control)
  z1 (AS65001) ── z2 (AS65002, 4 shards) ──┤
   PE, vrf-blue    VPNv6 relay (no VRF)    └── z4 (AS65004)  late peer  → sync
```

## Notes

All four on bridge br0 (2001:db8::x). z1 exports 2001:db8:1::/64 + 2001:db8:2::/64.

## Test Scenarios

| Scenario | Result |
|----------|--------|
| z1 (PE) and the sharded VPNv6 relay z2 come up; z2 holds the routes | |
| the late peer z4 gets the VPNv6 routes on sync | |
| z1 withdraws one route; the withdraw reaches the synced peer z4 | |
| z1's session drops; the peer-down sweep clears its routes from z4 | |
| Teardown topology | |
