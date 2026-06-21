# BGP iBGP-only attributes are stripped on eBGP egress (IPv6 unicast)

## Overview

As a network operator
I want the iBGP-only path attributes — ORIGINATOR_ID, CLUSTER_LIST and
LOCAL_PREF — to stay inside the AS for IPv6 unicast routes too
So that an iBGP-learned IPv6 route re-advertised to an eBGP peer does not
leak attributes that have meaning only within the local AS.
This is the IPv6 counterpart of @bgp_rr_ebgp_strip: the egress builder
`route_update_ipv6` clones the route's stored attrs, so without the
eBGP strip an iBGP-learned v6 route would carry ORIGINATOR_ID /
CLUSTER_LIST (RFC 4456 §8) and LOCAL_PREF (RFC 4271 §5.1.5) across the
AS boundary. Sessions are IPv6-transport so next-hop-self uses the
session's local v6 address directly.

## Test Topology

```
  ┌────────────────────────────────────────────────────────────────────────┐
  │                                  br0                                   │
  └────────┬──────────────────┬──────────────────┬──────────────────┬─────┘
           │                  │                  │                  │
      ┌────┴────┐        ┌────┴────┐        ┌────┴────┐        ┌────┴────┐
      │   z1    │  iBGP  │   z2    │        │   z3    │  eBGP  │   z4    │
      │  (RR)   │◀──────▶│(client) │        │(client) │◀──────▶│ (peer)  │
      │ AS65001 │        │ AS65001 │        │+ border │        │ AS65002 │
      │id 10.0. │        │id 10.0. │        │ AS65001 │        │id 10.0. │
      │   0.1   │        │   0.2   │        │id 10.0. │        │   0.4   │
      │2001:db8 │        │2001:db8 │        │   0.3   │        │2001:db8 │
      │   ::1   │        │   ::2   │        │2001:db8 │        │   ::4   │
      └────┬────┘        └─────────┘        │   ::3   │        └─────────┘
           │ iBGP (RR client)               └────┬────┘
           └─────────────────────────────────────┘
```

## Notes

- z1 is the route reflector; z2 and z3 are its clients (same AS 65001).
- z2 originates 2001:db8:beef::/64 and advertises it to the RR (z1).
- z1 REFLECTS the route to client z3, stamping ORIGINATOR_ID (z2's
  router-id 10.0.0.2) and CLUSTER_LIST (z1's cluster-id). z3 therefore
  sees the route WITH the iBGP-only attributes — the positive control.
- z3 re-advertises the route to its eBGP peer z4 (AS 65002). z4 MUST
  receive the route WITHOUT ORIGINATOR_ID / CLUSTER_LIST / LOCAL_PREF.

## Config Files

- z1.yaml: RR — iBGP to z2 and z3, both route-reflector clients.
- z2.yaml: client — iBGP to z1; originates 2001:db8:beef::/64.
- z3.yaml: client + border — iBGP to z1, eBGP to z4.
- z4.yaml: eBGP peer — eBGP to z3 only.

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Setup topology and establish BGP sessions | |
| RR client z3 receives the reflected route WITH the iBGP-only attributes | |
| eBGP peer z4 receives the route but NOT the iBGP-only attributes | |
| Teardown topology | |
