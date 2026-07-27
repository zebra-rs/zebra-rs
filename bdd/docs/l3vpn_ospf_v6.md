# SRv6 L3VPN (IPv6) with OSPFv3 PE-CE both segments

## Overview

As a service provider running L3VPN over SRv6 (zebra-rs has no 6VPE)
I want a full [C]-[CE]-[PE]-[P]-[PE]-[CE]-[C] topology where both the
C-CE and PE-CE segments run OSPFv3 and the PE does two-way
redistribution (OSPFv3<->VPNv6 over SRv6 End.DT46), so that C1 and C2
can reach each other's IPv6 loopback across the SRv6 core.
The PE runs the global IS-IS SRv6 core plus a per-VRF OSPFv3 to the CE.
Up: `router bgp vrf ... redistribute ospf` -> VPNv6. Down: `router
ospfv3 vrf ... redistribute bgp` -> the VPNv6 routes imported into the
VRF are injected into the CE-facing OSPFv3 as AS-External (Type-5)
LSAs (the net-new OSPFv3 feature added for this). The customer
loopbacks are advertised intra-area (OSPFv3 has no instance-level
redistribute-connected).

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Build the SRv6 L3VPN topology and bring up the core | |
| Customer routes are carried as VPNv6 (OSPFv3 -> BGP, up direction) | |
| End-to-end customer loopback reachability across the SRv6 core | |
| Teardown topology | |
