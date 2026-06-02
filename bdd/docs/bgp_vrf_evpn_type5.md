# BGP per-VRF EVPN Type-5 (IP Prefix) advertise to a remote PE

## Overview

As a network operator
I want a network configured under `router bgp vrf X afi-safi ipv4`
with `evpn advertise-ipv4` to be advertised as an EVPN Type-5
(RFC 9136 IP Prefix) route toward a remote PE
Using a two-namespace topology where z1 originates the prefix inside
vrf-blue and z2 peers with z1 over the L2VPN/EVPN address family,
imports the Type-5 route by matching route-target.
This is the EVPN-encoded counterpart of the VPNv4 export feature: the
same per-VRF state (RD, route-target, network) produces a Type-5 NLRI
instead of a VPNv4 NLRI, exchanged over (AFI=25 / SAFI=70).

## Test Topology

```
  ┌─────────────┐                ┌─────────────┐
  │     z1      │   EVPN iBGP    │     z2      │
  │  AS 65001   │ ◀────────────▶ │  AS 65001   │
  │ vrf-blue:   │                │ vrf-blue:   │
  │  RD 65001:  │                │  RD 65001:  │
  │   100       │                │   200       │
  │  RT 65001:  │                │  RT 65001:  │
  │   100 imp/  │                │   100 imp/  │
  │   exp       │                │   exp       │
  │  net 10.1.  │                │             │
  │   0.0/24    │                │             │
  │  evpn adv-  │                │             │
  │   ipv4      │                │             │
  └─────────────┘                └─────────────┘
   192.168.0.1                    192.168.0.2
```

## Config Files

- z1-1.yaml: AS 65001, vrf-blue with RD 65001:100, RT 65001:100, a
- z2-1.yaml: AS 65001, vrf-blue with RD 65001:200, RT 65001:100

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Setup topology | |
| z1 advertises the self-originated network as an EVPN Type-5 route | |
| z2 receives the EVPN Type-5 route under the originating RD | |
| Teardown topology | |
