# SR Policy egress carries a well-formed AS_PATH (IPv6)

## Overview

As a network operator distributing SR Policies over BGP (SAFI 73)
I want our own and reflected policies to carry a well-formed AS_PATH
So every neighbor accepts them, as RFC 4271 requires.

Our own SR Policies went out with no AS_PATH at all (a missing
well-known attribute) and a reflected policy went to an eBGP neighbor
without our AS prepended (RFC 4271 §5.1.2): a neighbor running
`enforce-first-as` rejected both. (A neighbor that comes up later is
still sent our own policies only; replaying reflected ones needs a store
of received policies, a follow-up.) The twin is
`bgp_sr_policy_egress`; this one uses IPv6 endpoints.

## Test Topology

```
   z4 (AS65004) ── eBGP ── z1 (AS65000) ── iBGP ── z2 (AS65000, RR) ── eBGP ── z3 (AS65003)
   enforce-first-as         origin        client                      enforce-first-as
```

## Notes

All four on bridge br0 10.0.69.0/24. z1 originates two policies, each
consumed by the neighbor whose router-id is its Route Target (RFC 9830
§4.2): GREEN for z3 (reflected by z2 onto eBGP) and BLUE for z4 (direct
eBGP).

## Config Files

- z1.yaml: the two policies; iBGP to z2 (its RR), eBGP to z4.
- z2.yaml: route reflector — z1 a client, eBGP to z3.
- z3.yaml, z4.yaml: enforce-first-as toward their neighbor.

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Setup; the sessions come up | |
| Our own policy is accepted by the eBGP neighbor | |
| A reflected policy is accepted by the eBGP neighbor | |
| Teardown topology | |
