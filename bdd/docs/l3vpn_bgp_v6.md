# SRv6 L3VPN (IPv6) with BGP PE-CE and a customer site

## Overview

As a service provider running L3VPN over SRv6 (zebra-rs has no 6VPE, so
IPv6 customer VPN traffic rides SRv6 End.DT46 rather than MPLS)
I want a full [C]-[CE]-[PE]-[P]-[PE]-[CE]-[C] topology where the
customer edge runs IPv6 eBGP to the PE and the customer site originates
an IPv6 loopback, so that C1 and C2 can reach each other's loopback
across the SRv6 VPNv6 core.

## Test Topology

```
   c1 --- ce1 --- pe1 --- p --- pe2 --- ce2 --- c2
   lo      |       lo     lo     lo      |       lo
  c1::1    |    db8::1  db8::2 db8::3    |     c2::1
           |   LOC1 fcbb:bbbb:1::/48     |
           |        LOC2 fcbb:bbbb:2::/48|
   AS65101 \_AS65001_/  vrf-cust  \_AS65002_/  AS65102
```

## Notes

- Core (pe1-p-pe2): IS-IS L2 SRv6; PE loopbacks + locators are reached
  natively over IPv6 through the P transit. pe1<->pe2 iBGP carries
  VPNv6 over v6 loopbacks; the per-VRF End.DT46 SID (from each PE's
  locator) is the service SID.
- PE-CE (ce<->pe, inside vrf-cust, encapsulation srv6): IPv6 eBGP;
  CE-learned routes export to VPNv6. Exercises the per-VRF neighbor
  `afi-safi ipv6 enabled` knob.
- C-CE (c<->ce): IPv6 eBGP; C redistributes its loopback (connected)
  into BGP and CE re-advertises it to the PE.
- The C1<->C2 IPv6 loopback ping exercises C-CE eBGP + PE-CE eBGP +
  VPNv6 over the SRv6 core (z2 H.Encaps toward z1's End.DT46, z1 decaps).

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Build the SRv6 L3VPN topology and bring up every session | |
| PE-PE VPNv6 and C-CE eBGP sessions are Established | |
| Customer loopbacks are exchanged as VPNv6 between the PEs | |
| End-to-end customer loopback reachability across the SRv6 core | |
| Teardown topology | |
