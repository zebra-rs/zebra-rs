# Per-VRF BGP neighbor per-AFI next-hop knobs (next-hop-self, next-hop-unchanged)

## Overview

As an operator of an L3VPN PE
I want `router bgp vrf <name> neighbor <addr> afi-safi ipv4
{next-hop-self | next-hop-unchanged}` to take effect on the plain
IPv4-unicast advertise toward a CE
So that the per-neighbor next-hop policy works on a PE-CE session — the
knobs used to be honored only on the VPNv4 / labeled-unicast paths and
were silently ignored for plain unicast.

CE1 advertises 10.0.1.1/32 with its own address 10.1.0.2 as the next-hop.
PE1 re-advertises it from the VRF Loc-RIB to the other CEs:

## Test Topology

```
   ce1(65001) ─┐
   ce2(65002) ─┼─ pe1 (65000, vrf-cust)
   ce3(65003) ─┤
   ce4(65000) ─┘   (ce4 is iBGP)
```

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Build the next-hop VRF topology | |
| next-hop-unchanged preserves the received next-hop toward an eBGP CE | |
| default eBGP advertisement rewrites the next-hop to self | |
| next-hop-self forces self toward an iBGP CE | |
| Teardown topology | |
