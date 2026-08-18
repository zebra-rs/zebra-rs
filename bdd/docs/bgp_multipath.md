# BGP multipath (maximum-paths)

## Overview

As a network operator
I want equal-cost eBGP paths installed together as one ECMP route
So that a leaf with several upstreams load-shares instead of pinning
all traffic to a single link.

## Test Topology

```
  ┌─────────────────────────────────────────────────────────┐
  │                          br0                            │
  └───────────┬───────────────┬───────────────┬─────────────┘
              │               │               │
         ┌────┴────┐     ┌────┴────┐     ┌────┴────┐
         │   z1    │     │   z2    │     │   z3    │
         │ AS65001 │     │ AS65002 │     │ AS65002 │
         │  (DUT)  │     │         │     │         │
         │192.168. │     │192.168. │     │192.168. │
         │  0.1/24 │     │  0.2/24 │     │  0.3/24 │
         └─────────┘     └─────────┘     └─────────┘
```

## Notes

z2 and z3 share AS 65002 and both advertise 10.99.0.0/24, so the two
paths z1 learns tie on every best-path comparison down to the
router-id tie-break — the multipath-eligible case. z1 runs
"maximum-paths 4" for ipv4 from the start.

## Config Files

- z1-1.yaml: AS 65001, peers to z2/z3, afi-safi ipv4 maximum-paths 4
- z2-1.yaml: AS 65002, network 10.99.0.0/24 (z2-2.yaml withdraws it)
- z3-1.yaml: AS 65002, network 10.99.0.0/24
- z3-2.yaml: same as z3-1 but AS 65003 (for the strict/relax split)

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Setup topology and establish BGP sessions | |
| Two equal-cost paths install as one ECMP route | |
| Withdrawing one upstream leaves the other leg installed | |
| Re-advertising restores the second leg | |
| Lowering maximum-paths at runtime withdraws the surplus leg | |
| Raising maximum-paths rediscovers the second leg | |
| Strict default does not load-share across two upstream ASes | |
| multipath-relax admits equal-length paths across ASes | |
| maximum-paths-ibgp is accepted and leaves eBGP sets alone | |
| Teardown topology | |
