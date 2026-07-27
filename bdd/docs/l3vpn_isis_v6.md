# SRv6 L3VPN (IPv6) with IS-IS PE-CE both segments

## Overview

As a service provider running L3VPN over SRv6 (zebra-rs has no 6VPE)
I want a full [C]-[CE]-[PE]-[P]-[PE]-[CE]-[C] topology where both the
C-CE and PE-CE segments run IS-IS (IPv6) and the PE does two-way
redistribution (IS-IS<->VPNv6 over SRv6 End.DT46), so that C1 and C2
can reach each other's IPv6 loopback across the SRv6 core.

The PE runs the global IS-IS SRv6 core plus a per-VRF IS-IS (IPv6) to
the CE. Up: `router bgp vrf ... redistribute isis` -> VPNv6. Down:
`router isis vrf ... afi-safi ipv6 redistribute bgp` -> the VPNv6
routes imported into the VRF are injected into the CE-facing IS-IS.

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Build the SRv6 L3VPN topology and bring up the core | |
| Customer routes are carried as VPNv6 (IS-IS -> BGP, up direction) | |
| End-to-end customer loopback reachability across the SRv6 core | |
| Teardown topology | |
