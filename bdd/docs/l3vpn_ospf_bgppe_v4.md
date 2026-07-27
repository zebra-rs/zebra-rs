# MPLS/VPN L3VPN (IPv4) with OSPFv2 C-CE and BGP PE-CE

## Overview

Second L3VPN PE-CE variant: the customer runs OSPFv2 to the CE, but the
CE-PE link is eBGP (not OSPF). The CE bridges the two with mutual
redistribution (OSPF<->BGP); the PE is a plain BGP PE-CE edge. So C1
and C2 reach each other's loopback across the MPLS/VPN core.

vs @l3vpn_ospf_v4 (OSPF on both segments): here the PE has no VRF OSPF
— it runs an eBGP PE-CE session into vrf-cust like @l3vpn_bgp_v4, and
the CE does `redistribute ospf`->BGP (up) and `redistribute bgp`->OSPF
(down).

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Build the L3VPN topology and bring up the core | |
| Customer routes are carried as VPNv4 (CE OSPF->eBGP, up direction) | |
| Remote customer loopbacks reach the customer site (CE eBGP->OSPF, down direction) | |
| End-to-end customer loopback reachability across the MPLS/VPN core | |
| Teardown topology | |
