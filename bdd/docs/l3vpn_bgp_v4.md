# MPLS/VPN L3VPN (IPv4) with BGP PE-CE and a customer site

## Overview

As a service provider running RFC 4364 L3VPN over SR-MPLS
I want a full [C]-[CE]-[PE]-[P]-[PE]-[CE]-[C] topology where the
customer edge runs eBGP to the PE and the customer site originates a
loopback, so that C1 and C2 can reach each other's loopback across the
MPLS/VPN core (VPNv4 over an SR-MPLS LSP through the P transit).

## Test Topology

```
   c1 --- ce1 --- pe1 --- p --- pe2 --- ce2 --- c2
   lo      |       lo     lo     lo      |       lo
  10.0.1.1 |    1.1.1.1 1.1.1.2 1.1.1.3  |    10.0.2.1
           |    (sid 1) (sid 2) (sid 3)  |
   AS65101 \_AS65001_/  vrf-cust  \_AS65002_/  AS65102
```

## Notes

- Core (pe1-p-pe2): IS-IS L2 + segment-routing mpls; loopback
  Prefix-SIDs build the PE-PE transport LSP (SRGB 16000), P is the
  transit LSR. pe1<->pe2 iBGP carries VPNv4 over loopbacks.
- PE-CE (ce<->pe, inside vrf-cust): eBGP; CE-learned routes export to
  VPNv4 (RD 65000:1 / 65000:2, RT 65000:100).
- C-CE (c<->ce): eBGP; C redistributes its loopback (connected) into
  BGP and CE re-advertises it to the PE.
- The C1<->C2 loopback ping exercises C-CE eBGP + PE-CE eBGP + VPNv4
  over the SR-MPLS core.

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Build the L3VPN topology and bring up every session | |
| SR-MPLS transport LSPs are installed on the core P router | |
| PE-PE VPNv4 and C-CE eBGP sessions are Established | |
| Customer loopbacks are exchanged as VPNv4 between the PEs | |
| End-to-end customer loopback reachability across the MPLS/VPN core | |
| Teardown topology | |
