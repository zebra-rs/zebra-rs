# The best path does not depend on the order paths arrived in, with MED in play (IPv4)

## Overview

As a network operator
I want best-path selection to give one answer for one set of paths
So neither the order my neighbors' routes arrived in nor an unchanged
re-advertisement moves my best path, my FIB and my advertisements.

MED is compared only between paths from the same neighboring AS, so the
pairwise comparison is not transitive. zebra-rs picked the winner with
one linear pass over the candidate list, so the answer depended on the
list's order — and a replaced path moves to the tail of that list, so
re-advertising an unchanged path could change the winner. Deterministic
MED settles it: pick the best path within each neighboring AS first
(MED applies), then compare those (MED does not).

## Test Topology

```
    ┌──────────────────────────────────────────────────────────┐
    │                   br0 192.168.54.0/24                    │
    └─────┬───────────┬───────────┬───────────┬───────────┬────┘
     ┌────┴───┐  ┌────┴───┐  ┌────┴───┐  ┌────┴───┐  ┌────┴───┐
     │   h1   │  │   h2   │  │   h3   │  │   z1   │  │   z2   │
     │   A    │  │   B    │  │   C    │  │ (DUT)  │  │        │
     │AS65081 │  │AS65082 │  │AS65081 │  │AS65001 │  │AS65090 │
     │ MED 10 │  │ no MED │  │ MED 5  │  │        │  │        │
     │   .2   │  │   .3   │  │   .4   │  │   .1   │  │   .5   │
     └────────┘  └────────┘  └────────┘  └────────┘  └────────┘
```

## Notes

h1, h2 and h3 run tests/scripts/bgp_attr_inject_send.py and announce
10.54.0.0/24, each with the same AS_PATH length and its own community:
A = 65081:1 (MED 10), B = 65082:2 (no MED), C = 65081:3 (MED 5). Their
BGP Identifiers order A < B < C. Deterministic MED: C beats A on MED
(same neighboring AS), then B beats C on BGP Identifier — B is the best
path. The paths arrive in the order A, B, C, for which the linear pass
chose C. On the trigger file /tmp/bgp_med_order_independent.go, h1
re-announces A unchanged plus the control prefix 10.54.1.0/24; the
linear pass then chose A. z2 shows which path z1 selected.

## Config Files

- z1.yaml: DUT — eBGP to h1, h2, h3 (passive) and to z2.
- z2.yaml: z1's downstream eBGP neighbor.

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Setup topology; the three paths arrive in the order A, B, C | |
| z1 selects B, the deterministic-MED best path | |
| An unchanged re-advertisement does not move the best path | |
| Teardown topology | |
