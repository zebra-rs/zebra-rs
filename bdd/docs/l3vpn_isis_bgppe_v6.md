# SRv6 L3VPN (IPv6) with IS-IS C-CE and BGP PE-CE

## Overview

Second L3VPN PE-CE variant over SRv6: the customer runs IS-IS (IPv6) to
the CE, the CE-PE link is IPv6 eBGP, and the CE bridges them with
mutual redistribution (IS-IS<->BGP). The PE is a plain BGP PE-CE edge
(like @l3vpn_bgp_v6). C1 and C2 reach each other's IPv6 loopback across
the SRv6 core.

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Build the SRv6 L3VPN topology and bring up the core | |
| Customer routes are carried as VPNv6 (CE IS-IS->eBGP, up direction) | |
| End-to-end customer loopback reachability across the SRv6 core | |
| Teardown topology | |
