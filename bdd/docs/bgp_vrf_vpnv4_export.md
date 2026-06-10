# BGP per-VRF VPNv4 export to a remote PE

## Overview

As a network operator
I want to advertise a network configured under `router bgp vrf X
afi-safi ipv4` as a VPNv4 NLRI toward a remote PE
Using a two-namespace topology where z1 originates the prefix
inside vrf-blue and z2 peers with z1 over VPNv4 only.

## Test Topology

```
  ┌─────────────┐                ┌─────────────┐
  │     z1      │   VPNv4 iBGP   │     z2      │
  │  AS 65001   │ ◀────────────▶ │  AS 65001   │
  │ vrf-blue:   │                │ vrf-blue:   │
  │  RD 65001:  │                │  RD 65001:  │
  │   100       │                │   200       │
  │  RT 65001:  │                │  RT 65001:  │
  │   100 imp/  │                │   100 imp/  │
  │   exp       │                │   exp       │
  │  net 10.1.  │                │             │
  │   0.0/24    │                │             │
  └─────────────┘                └─────────────┘
   192.168.0.1                    192.168.0.2
```

## Config Files

- z1-1.yaml: AS 65001, vrf-blue with RD 65001:100, RT 65001:100,
- z2-1.yaml: AS 65001, vrf-blue with RD 65001:200, RT 65001:100

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Setup topology | |
| z1 advertises the self-originated network as VPNv4 | |
| z2 receives the VPNv4 NLRI under the same RD | |
| VPNv4 route detail by address and by exact prefix | |
| Teardown topology | |
