# EVPN Type-5 (IP Prefix) over SRv6 — End.DT46 dataplane forwarding

## Overview

As a service provider carrying L3VPN as EVPN rather than VPNv4/VPNv6
I want a VRF's IPv4 and IPv6 prefixes advertised as EVPN Type-5 routes
(RFC 9136) carrying the per-VRF End.DT46 service SID (RFC 9252), and the
receiving PE to install them into the VRF as SRv6 H.Encaps routes, so
that customer hosts forward end to end with EVPN as the only negotiated
address family.

This is the forwarding-level counterpart of @bgp_vrf_evpn_type5, which
proves the control-plane round trip over MPLS-less defaults. Here the
encoding change (VPNv4/VPNv6 NLRI -> Type-5 NLRI) is held against the
SRv6 dataplane that @mirror_sid_vpnsrv6_base proves for VPNv4/VPNv6:
same VRF, same locators, same End.DT46 SID, same pings — only the NLRI
encoding differs. The peers negotiate ONLY (AFI=25 / SAFI=70), so a
passing ping cannot be a VPNv4/VPNv6 path in disguise.

```
```

## Config Files

- z1.yaml, z2.yaml — dual-stack vrf-cust, `encapsulation srv6`, and

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Build the topology and bring up the EVPN session | |
| Each PE carves a local End.DT46 service SID from its locator | |
| Both AFIs are advertised as Type-5 NLRI under the originating RD | |
| The received Type-5 routes carry the originator's End.DT46 SID | |
| Imported Type-5 routes install into the VRF as SRv6 encapsulation | |
| CE-to-CE traffic forwards over the Type-5 SRv6 dataplane | |
| Withdrawing a network withdraws the Type-5 route and its FIB entry | |
| Teardown topology | |
