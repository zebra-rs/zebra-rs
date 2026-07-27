# MPLS/VPN L3VPN (IPv4) with static PE-CE and a customer site

## Overview

As a service provider running RFC 4364 L3VPN over SR-MPLS
I want a full [C]-[CE]-[PE]-[P]-[PE]-[CE]-[C] topology where the PE-CE
and C-CE segments are statically routed and the PE redistributes the
customer static route into VPNv4, so that C1 and C2 can reach each
other's loopback across the MPLS/VPN core.

Test Topology (7 namespaces) — same core as @l3vpn_bgp_v4; the customer
side is static instead of eBGP:
```
10.0.1.1 |    1.1.1.1 1.1.1.2 1.1.1.3  |    10.0.2.1
```
- Core (pe1-p-pe2): IS-IS L2 + segment-routing mpls; iBGP VPNv4.
- PE-CE: PE holds a per-VRF static route to the customer loopback via

## Notes

- Core (pe1-p-pe2): IS-IS L2 + segment-routing mpls; iBGP VPNv4.
- PE-CE: PE holds a per-VRF static route to the customer loopback via
  the CE and `redistribute static` into VPNv4. The CE has a static
  route to the customer loopback and a default toward the PE; the
  customer has a default toward the CE. Down-direction traffic rides
  the CE/customer default routes.

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Build the L3VPN topology and bring up the core | |
| SR-MPLS transport LSPs are installed on the core P router | |
| PE-PE VPNv4 session is Established and carries the customer loopbacks | |
| End-to-end customer loopback reachability across the MPLS/VPN core | |
| Teardown topology | |
