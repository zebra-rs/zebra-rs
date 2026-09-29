# The group egress engine withdraws from the first neighbor too

## Overview

As a network operator running the per-update-group egress engine
(ZEBRA_BGP_EGRESS_GROUP_TASK=1)
I want a route withdrawn because its next-hop stopped resolving to leave
every neighbor it was sent to
So no neighbor keeps forwarding to us on a route we no longer have.

The engine's withdraw skipped the neighbor its caller named as the
route's source. The next-hop re-evaluation names none and passes 0 —
the index of the first configured neighbor — so that neighbor kept the
route. The engine serves IPv4 unicast only, so there is no IPv6 twin.

## Test Topology

```
  ┌──────────────────────────────────────────────────────────────┐
  │                     br0 192.168.65.0/24                      │
  └──────┬───────────────┬───────────────┬───────────────┬───────┘
    ┌────┴────┐     ┌────┴────┐     ┌────┴────┐     ┌────┴────┐
    │   z1    │     │   z3    │     │   h1    │     │   z4    │
    │  (DUT)  │     │  plain  │     │scripted │     │  plain  │
    │ AS65001 │     │ AS65093 │     │ AS65091 │     │ AS65094 │
    │  .1     │     │  .2     │     │  .3     │     │  .4     │
    └─────────┘     └─────────┘     └─────────┘     └─────────┘
```

## Notes

z1 runs the group egress engine. Its neighbors are configured in address
order, so z3 is the first (index 0), h1 the second and z4 the third; z3
and z4 share one update group. h1
(tests/scripts/bgp_attr_inject_send.py) announces 10.65.1.0/24 with the
third-party next-hop 10.65.99.2, which z1 resolves through the static
route 10.65.99.0/24 via h1; deleting that route makes it unreachable.

## Config Files

- z1.yaml: DUT — the static route; eBGP to z3, h1 (passive) and z4.
- z3.yaml, z4.yaml: z1's plain neighbors.

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Setup topology; z3 and z4 learn the prefix | |
| The next-hop stops resolving; both neighbors lose the route | |
| The next-hop resolves again; both neighbors get the route back | |
| Teardown topology | |
