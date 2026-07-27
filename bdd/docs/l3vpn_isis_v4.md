# MPLS/VPN L3VPN (IPv4) with IS-IS PE-CE both segments

## Overview

As a service provider running RFC 4364 L3VPN over SR-MPLS
I want a full [C]-[CE]-[PE]-[P]-[PE]-[CE]-[C] topology where both the
C-CE and PE-CE segments run IS-IS and the PE does two-way
redistribution (IS-IS<->VPNv4), so that C1 and C2 can reach each
other's loopback across the MPLS/VPN core.

The PE runs two IS-IS instances: the GLOBAL core (IS-IS L2 + SR-MPLS)
and a per-VRF IS-IS (vrf-cust) toward the CE. Up: `router bgp vrf ...
redistribute isis` -> VPNv4. Down: `router isis vrf ... redistribute
bgp` -> the VPNv4 routes imported into the VRF are injected into the
CE-facing IS-IS (IS-IS already supports redistribute bgp; only the
per-VRF redist subscription proto needed fixing).

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Build the L3VPN topology and bring up the core | |
| Customer routes are carried as VPNv4 (IS-IS -> BGP, up direction) | |
| Remote customer loopbacks reach the customer site (BGP -> IS-IS, down direction) | |
| End-to-end customer loopback reachability across the MPLS/VPN core | |
| Teardown topology | |
