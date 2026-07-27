# MPLS/VPN L3VPN (IPv4) with IS-IS C-CE and BGP PE-CE

## Overview

Second L3VPN PE-CE variant: the customer runs IS-IS to the CE, the
CE-PE link is eBGP, and the CE bridges them with mutual redistribution
(IS-IS<->BGP). The PE is a plain BGP PE-CE edge (like @l3vpn_bgp_v4).
C1 and C2 reach each other's loopback across the MPLS/VPN core.

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Build the L3VPN topology and bring up the core | |
| Customer routes are carried as VPNv4 (CE IS-IS->eBGP, up direction) | |
| Remote customer loopbacks reach the customer site (CE eBGP->IS-IS, down direction) | |
| End-to-end customer loopback reachability across the MPLS/VPN core | |
| Teardown topology | |
