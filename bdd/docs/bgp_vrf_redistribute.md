# BGP per-VRF redistribute connected/static to VPNv4

## Overview

As a network operator
I want `router bgp vrf X afi-safi ipv4 redistribute {connected,static}`
to pull a VRF's connected and static routes into the per-VRF BGP table
and export them to VPNv4 toward a remote PE — the IOS-XR L3VPN model,
without a CE-facing routing protocol.

## Test Topology

```
   h1(10.1.0.2) ── z1[vrf-blue]  ── VPNv4 iBGP ──  z2[vrf-blue]
                   vc1 10.1.0.1/24                  RD 65001:200
                   static 10.2.0.0/24               RT 65001:100 import
                   RD 65001:100, RT 65001:100
                   redistribute connected + static
   192.168.0.1 ───────────── br0 ───────────── 192.168.0.2
```

## Config Files

- z1-1.yaml: AS 65001, vrf-blue (RD 65001:100, RT 65001:100), vc1 in
- z2-1.yaml: AS 65001, vrf-blue (RD 65001:200, RT 65001:100 import).

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Setup topology | |
| The VRF connected route lands in the VRF table (Phase 0 prereq) | |
| z1 redistributes the VRF connected + static routes as VPNv4 | |
| z2 receives the redistributed VRF prefixes as VPNv4 under z1's RD | |
| Teardown topology | |
