# Per-VRF BGP neighbor AddPath send (RFC 7911)

## Overview

As an operator of an L3VPN PE with redundant CE uplinks
I want `router bgp vrf <name> neighbor <addr> afi-safi ipv4 add-path
send-receive` to advertise every VRF path for a prefix
So that a CE that negotiated AddPath receives BOTH paths for a
multi-homed prefix, not just the single best one — the per-VRF exercise
of AddPath send / path-id stamping.

CE1 (65001) and CE2 (65002) both advertise 10.10.10.0/24 into vrf-cust,
so PE1's VRF Loc-RIB holds two candidate paths. With AddPath negotiated
toward CE3, PE1 advertises both, so CE3 sees two paths — one via AS 65001
and one via AS 65002. Without AddPath send CE3 would hold only the single
best path (one AS_PATH).

## Test Topology

```
   ce1(65001) ─┐
   ce2(65002) ─┼─ pe1 (65000, vrf-cust) ── ce3(65003, AddPath rx)
```

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Build the AddPath VRF topology | |
| PE1's VRF Loc-RIB holds both candidate paths | |
| The AddPath receiver sees both paths for the prefix | |
| Teardown topology | |
