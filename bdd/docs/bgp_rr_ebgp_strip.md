# BGP iBGP-only attributes are stripped on eBGP egress

## Overview

As a network operator
I want the iBGP-only path attributes — ORIGINATOR_ID, CLUSTER_LIST and
LOCAL_PREF — to stay inside the AS
So that an iBGP-learned route re-advertised to an eBGP peer does not leak
attributes that have meaning only within the local AS.
RFC 4456 §8 defines ORIGINATOR_ID (type 9) and CLUSTER_LIST (type 10) as
optional NON-TRANSITIVE attributes that carry meaning only within the
local AS (the originating router-id and the intra-AS reflection path).
They MUST NOT cross an AS boundary: leaking them risks spurious loop
drops at a remote AS that happens to share a router-id / cluster-id.
RFC 4271 §5.1.5 likewise forbids sending LOCAL_PREF to external peers.

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
      │192.168. │        │192.168. │        │   0.3   │        │192.168. │
      │  0.1/24 │        │  0.2/24 │        │192.168. │        │  0.4/24 │
      └────┬────┘        └─────────┘        │  0.3/24 │        └─────────┘
           │ iBGP (RR client)               └────┬────┘
           └─────────────────────────────────────┘
```

## Notes

- z1 is the route reflector; z2 and z3 are its clients (same AS 65001).
- z2 originates 10.10.10.0/24 and advertises it to the RR (z1).
- z1 REFLECTS the route to client z3, stamping ORIGINATOR_ID (z2's
  router-id 10.0.0.2) and CLUSTER_LIST (z1's cluster-id). z3 therefore
  sees the route WITH the route-reflection attributes — the positive
  control proving the route really traversed a reflector.
- z3 re-advertises the route to its eBGP peer z4 (AS 65002). z4 MUST
  receive the route WITHOUT ORIGINATOR_ID / CLUSTER_LIST.

## Config Files

- z1.yaml: RR — iBGP to z2 and z3, both route-reflector clients.
- z2.yaml: client — iBGP to z1; originates 10.10.10.0/24.
- z3.yaml: client + border — iBGP to z1, eBGP to z4.
- z4.yaml: eBGP peer — eBGP to z3 only.

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Setup topology and establish BGP sessions | |
| RR client z3 receives the reflected route WITH the iBGP-only attributes | |
| eBGP peer z4 receives the route but NOT the iBGP-only attributes | |
| Teardown topology | |
