# An AddPath neighbor follows the next-hop's reachability (IPv6)

## Overview

As a network operator
I want an AddPath neighbor to lose a path when its next-hop stops
resolving, and to get it back when the next-hop resolves again
So the neighbor never forwards on a path we cannot forward on.

A path whose next-hop does not resolve is not eligible (RFC 4271
§9.1.2.1). A plain neighbor follows the selection, which leaves such a
path out. An AddPath neighbor is sent every candidate: the IPv6-unicast
next-hop re-evaluation re-ran the AddPath loop, which sent the
unreachable path again, so the AddPath neighbor kept it. IPv6 unicast
over IPv4 sessions. The IPv4 twin is `bgp_addpath_nht`.

## Test Topology

```
  ┌──────────────────────────────────────────────────────────────┐
  │                     br0 192.168.65.0/24                      │
  └──────┬───────────────┬───────────────┬───────────────┬───────┘
    ┌────┴────┐     ┌────┴────┐     ┌────┴────┐     ┌────┴────┐
    │   h1    │     │   z1    │     │   z2    │     │   z3    │
    │scripted │     │  (DUT)  │     │ AddPath │     │  plain  │
    │ AS65091 │     │ AS65001 │     │ AS65092 │     │ AS65093 │
    │  .2     │     │  .1     │     │  .3     │     │  .4     │
    └─────────┘     └─────────┘     └─────────┘     └─────────┘
```

## Notes

h1 (tests/scripts/bgp_attr_inject_send.py) announces 2001:db8:64:1::/64 with the
third-party next-hop 2001:db8:64:99::2. z1 resolves it through the static route
2001:db8:64:99::/64 via h1; deleting that route makes it unreachable,
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
