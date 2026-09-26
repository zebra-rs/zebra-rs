# An AddPath neighbor follows the next-hop's reachability (IPv4, sharded RIB)

## Overview

As a network operator
I want an AddPath neighbor to lose a path when its next-hop stops
resolving, and to get it back when the next-hop resolves again
So the neighbor never forwards on a path we cannot forward on.

`bgp_addpath_nht` with z1's IPv4-unicast RIB sharded (4 shards). There
the next-hop re-evaluation runs in the shards, which report the new
selection but no AddPath change, so the AddPath neighbor kept the path
after its next-hop stopped resolving.

## Test Topology

```
  ┌──────────────────────────────────────────────────────────────┐
  │                     br0 192.168.66.0/24                      │
  └──────┬───────────────┬───────────────┬───────────────┬───────┘
    ┌────┴────┐     ┌────┴────┐     ┌────┴────┐     ┌────┴────┐
    │   h1    │     │   z1    │     │   z2    │     │   z3    │
    │scripted │     │  (DUT)  │     │ AddPath │     │  plain  │
    │ AS65091 │     │ AS65001 │     │ AS65092 │     │ AS65093 │
    │  .2     │     │  .1     │     │  .3     │     │  .4     │
    └─────────┘     └─────────┘     └─────────┘     └─────────┘
```

## Notes

h1 (tests/scripts/bgp_attr_inject_send.py) announces 10.66.1.0/24 with the
third-party next-hop 10.66.99.2. z1 resolves it through the static route
10.66.99.0/24 via h1; deleting that route makes it unreachable,
adding it back makes it reachable again.

## Config Files

- z1.yaml: DUT — the static route; eBGP to h1 (passive), AddPath eBGP to
  z2, plain eBGP to z3.
- z2.yaml: z1's AddPath neighbor. z3.yaml: z1's plain neighbor.

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Setup topology; z2 and z3 learn the prefix | |
| The next-hop stops resolving; both neighbors lose the path | |
| The next-hop resolves again; both neighbors get the path back | |
| Teardown topology | |
