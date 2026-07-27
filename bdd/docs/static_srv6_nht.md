# Static route inherits SRv6 segments from its covering route

## Overview

As a network operator
I want a static route whose gateway is reachable only through a
BGP-over-SRv6 service route to resolve recursively through it and
inherit the H.Encap segment list — the SRv6 analog of the SR-MPLS
label inheritance in @isis_srmpls.

## Test Topology

```
  ┌────┐ eth0 ── i2 ┌────────┐ i1 ──────── i1 ┌────────┐ i2 ─────── i1 ┌────────┐
  │ h1 │────────────│   z1   │────────────────│   z2   │───────────────│   z3   │
  └────┘3001:db8::/64 egress │2001:db8:12::/64│  core  │2001:db8:23::/64 ingress│
   3001:db8::1      │ LOC1   │                │        │               │        │
                    └────────┘                └────────┘               └────────┘
   cust0 on z1: 2001:db8:cafe::1/64      z2 knows ONLY the two links
   (dummy — the gateway anchor)          and z1's locator fcbb:bbbb:1::/48
```

## Notes

- z1 advertises locator LOC1 (fcbb:bbbb:1::/48) and redistributes
  connected into BGP with `segment-routing srv6 ipv6-unicast`, so its
  prefixes (h1's subnet, the cust0 anchor) carry the End.DT6 SID
  fcbb:bbbb:1:40::.
- z3 receives them over `encapsulation-type srv6` and installs
  H.Encaps service routes.
- The static under test on z3, `3001:db8::1/128 via 2001:db8:cafe::1`,
  has a gateway covered ONLY by the 2001:db8:cafe::/64 SRv6 route:
  NHT must resolve through it and inherit that route's segment list.
  The transit core z2 knows nothing about the service prefixes, so
  the end-to-end ping to the host h1 behind z1 proves the inherited
  encapsulation carried the traffic (decap at z1's End.DT6, plain
  IPv6 delivery to h1).
- Deleting the static releases its seg6 nexthop group and forwarding
  falls back to the BGP /64 covering h1's subnet.

## Config Files

- z1.yaml, z2.yaml, z3.yaml

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Setup topology and converge BGP over SRv6 | |
| Static route resolves through the SRv6 route and inherits its segments | |
| Deleting the static falls back to the covering BGP route | |
| Teardown topology | |
