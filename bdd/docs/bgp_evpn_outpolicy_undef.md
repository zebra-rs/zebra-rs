# EVPN outbound policy rebound to an undefined name is deny-all

## Overview

As a network operator
I want a BGP neighbor whose EVPN outbound policy is rebound to a
policy name that does not exist to immediately withdraw the routes it
was advertising, rather than keep leaking them with the previously
resolved policy still applied.
A bound-but-unresolved peer policy is deny-all. Previously the policy
actor stayed silent when a peer registered an undefined policy name, so
no soft-reconfiguration fired and the stale resolved policy lingered:
the neighbor kept advertising. The actor now answers even with a `None`
policy, which clears the stale resolve and drives a soft-out that
withdraws the now-denied routes — all without a session reset.
The exercise: z1 originates 10.1.0.0/24 in vrf-blue and advertises it to
z2 as an EVPN Type-5 route. z1's EVPN outbound policy starts bound to an
existing PERMIT-ALL policy (z2 sees the route), is then rebound to the
undefined NOPE (z2 must lose the route), and finally NOPE is defined as
permit (z2 must see the route again).

## Test Topology

```
  ┌─────────────────────────────────────────┐
  │                   br0                   │
  └─────────────┬───────────────┬───────────┘
                │               │
           ┌────┴────┐     ┌────┴────┐
           │   z1    │     │   z2    │
           │ AS65001 │     │ AS65001 │
           │192.168. │     │192.168. │
           │  0.1/24 │     │  0.2/24 │
           └─────────┘     └─────────┘
```

## Config Files

- z1-permit.yaml: vrf-blue originates 10.1.0.0/24, EVPN out-policy bound
- z1-undef.yaml: EVPN out-policy rebound to the undefined NOPE.
- z1-recover.yaml: NOPE defined as a permit policy.
- z2-1.yaml: EVPN receiver importing RT 65001:100 into vrf-blue.

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Setup topology and verify the route is advertised under PERMIT-ALL | |
| Rebinding the EVPN out-policy to an undefined name withdraws the route | |
| Defining the previously-undefined policy re-advertises the route | |
| Teardown topology | |
