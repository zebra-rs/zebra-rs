# BGP per-VRF redistribute OSPF to VPNv4

## Overview

As a network operator
I want `router bgp vrf X afi-safi ipv4 redistribute ospf` to pull a
VRF's OSPF-learned routes (installed by a per-VRF OSPF instance into
the VRF table) into the per-VRF BGP table and export them to VPNv4 —
so a PE advertises CE-learned IGP routes into the L3VPN.

## Test Topology

```
   ce(OSPF) ── oc1 ── z1[vrf-blue: ospf + bgp] ── VPNv4 iBGP ── z2[vrf-blue]
   lo 10.9.9.9/32     10.0.0.1/30 (vrf-blue)                    RD 65001:200
   area 0             router ospf vrf vrf-blue                  RT 65001:100 imp
                      redistribute ospf, RD 65001:100
   10.0.0.2/30 ───────────── (veth) ──────────
   192.168.0.1 ───────────── br0 ───────────── 192.168.0.2
```

## Config Files

- ce.yaml: OSPF only; lo 10.9.9.9/32 + eth0 10.0.0.2/30 in area 0.
- z1-1.yaml: vrf-blue (RD 65001:100, RT 65001:100), oc1 in the VRF
  (10.0.0.1/30), `router ospf vrf vrf-blue` on oc1, `afi-safi ipv4
  redistribute ospf`, VPNv4 iBGP to z2.
- z2-1.yaml: vrf-blue (RD 65001:200, RT 65001:100 import), VPNv4 iBGP
  to z1.

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Setup topology | |
| z1 learns the CE's OSPF route in the VRF table | |
| z1 redistributes the VRF OSPF route as VPNv4, not the connected link | |
| z2 receives the redistributed OSPF prefix as VPNv4 under z1's RD | |
| Teardown topology | |
