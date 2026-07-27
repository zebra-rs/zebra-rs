# Per-VRF BGP neighbor route-reflector client

## Overview

As an operator running iBGP CE peers inside a VRF
I want `router bgp vrf <name> neighbor <addr> route-reflector client` to
reflect iBGP-learned routes to that CE
So that route reflection works on a per-VRF CE session exactly as on a
global neighbor — an iBGP-learned route reaches a client but not a
plain iBGP peer.
All three CEs are iBGP (AS 65000, same as PE1). CE1 originates
10.0.1.1/32. iBGP-learned routes are not re-advertised to another iBGP
peer unless that peer is a route-reflector client:

## Test Topology

```
   ce1(65000) ─┐
   ce2(65000) ─┼─ pe1 (65000, vrf-cust, route reflector)
   ce3(65000) ─┘
```

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Build the route-reflector VRF topology | |
| A route-reflector client receives the reflected iBGP route | |
| A plain iBGP peer does not receive the reflected route | |
| Teardown topology | |
