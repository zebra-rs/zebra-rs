# SRv6 L3VPN (IPv6) with static PE-CE and a customer site

## Overview

As a service provider running L3VPN over SRv6 (zebra-rs has no 6VPE)
I want a full [C]-[CE]-[PE]-[P]-[PE]-[CE]-[C] topology where the PE-CE
and C-CE segments are statically routed and the PE redistributes the
customer static route into VPNv6 (End.DT46), so that C1 and C2 can
reach each other's IPv6 loopback across the SRv6 core.
Same core as @l3vpn_bgp_v6 (IS-IS L2 SRv6, iBGP VPNv6); the customer
side is static instead of eBGP. The PE holds per-VRF static routes to
the customer loopback + C-CE link via the CE and `redistribute static`;
the CE/customer use default routes for the down direction.

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Build the SRv6 L3VPN topology and bring up the core | |
| PE-PE VPNv6 session is Established and carries the customer loopbacks | |
| End-to-end customer loopback reachability across the SRv6 core | |
| Teardown topology | |
