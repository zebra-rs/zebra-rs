# SRv6 L3VPN (IPv6) with OSPFv3 C-CE and BGP PE-CE

## Overview

Second L3VPN PE-CE variant over SRv6: the customer runs OSPFv3 to the
CE, the CE-PE link is IPv6 eBGP, and the CE bridges them with mutual
redistribution (OSPFv3<->BGP). The PE is a plain BGP PE-CE edge like the
l3vpn_bgp_v6 feature. C1 and C2 reach each other's IPv6 loopback across
the SRv6 core. Exercises the relayed-SRv6-SID strip on the PE->CE eBGP
advertisement (the CE is non-SRv6).

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Build the SRv6 L3VPN topology and bring up the core | |
| Customer routes are carried as VPNv6 (CE OSPFv3->eBGP, up direction) | |
| End-to-end customer loopback reachability across the SRv6 core | |
| Teardown topology | |
