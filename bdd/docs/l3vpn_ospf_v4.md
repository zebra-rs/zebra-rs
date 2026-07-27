# MPLS/VPN L3VPN (IPv4) with OSPFv2 PE-CE both segments

## Overview

As a service provider running RFC 4364 L3VPN over SR-MPLS
I want a full [C]-[CE]-[PE]-[P]-[PE]-[CE]-[C] topology where both the
C-CE and PE-CE segments run OSPFv2 and the PE does two-way
redistribution (OSPF<->VPNv4), so that C1 and C2 can reach each other's
loopback across the MPLS/VPN core.
Same core as @l3vpn_bgp_v4 (IS-IS L2 + SR-MPLS, iBGP VPNv4). The
customer side runs OSPFv2 in area 0 (C-CE and CE-PE). The PE:
- `router bgp vrf ... redistribute ospf` carries the customer routes
- `router ospf vrf ... redistribute bgp` injects the VPNv4 routes

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Build the L3VPN topology and bring up the core | |
| Customer routes are carried as VPNv4 (OSPF -> BGP, up direction) | |
| Remote customer loopbacks reach the customer site (BGP -> OSPF, down direction) | |
| End-to-end customer loopback reachability across the MPLS/VPN core | |
| Teardown topology | |
