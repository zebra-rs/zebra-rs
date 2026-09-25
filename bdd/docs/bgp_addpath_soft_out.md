# An outbound re-sync toward an AddPath neighbor reconciles every path-id (IPv4)

## Overview

As a network operator
I want an out-policy change on an AddPath neighbor to re-evaluate every
path I sent it, and to withdraw the ones the policy now denies under
their own path-ids
So the neighbor ends up holding exactly what the new policy permits.

An out-policy change (or `clear bgp … soft out`) re-syncs the neighbor
from the Loc-RIB. For IPv4 unicast and VPNv4 that re-sync read the best
path only and withdrew with path-id 0. Toward an AddPath neighbor that
left the non-best paths unexamined, and a path-id-0 withdraw carries no
path-id field at all — the neighbor reads it as an empty withdraw and
keeps the paths. The IPv6 twin (`bgp_addpath_soft_out_v6`) is the
control: the IPv6 re-sync reconciles by path-id already.

## Test Topology

```
  ┌──────────────────────────────────────────────────────────────┐
  │                     br0 192.168.62.0/24                      │
  └──────┬───────────────┬───────────────┬───────────────┬───────┘
    ┌────┴────┐     ┌────┴────┐     ┌────┴────┐     ┌────┴────┐
    │   h1    │     │   h2    │     │   z1    │     │   z2    │
    │scripted │     │scripted │     │  (DUT)  │     │ AddPath │
    │ AS65081 │     │ AS65082 │     │ AS65001 │     │ AS65072 │
    │  .2     │     │  .3     │     │  .1     │     │  .4     │
    └─────────┘     └─────────┘     └─────────┘     └─────────┘
```

## Notes

h1 announces 10.62.1.0/24 with AS_PATH "65081", h2 with "65082 65009
65010" (tests/scripts/bgp_attr_inject_send.py). z1 sends both paths to
z2 with AddPath. Then z1's out-policy toward z2 changes twice, each
followed by a soft-out: first to deny paths whose AS_PATH (as sent, with
z1's AS) has three or more ASes — h2's path only — then to deny
everything.

## Config Files

- z1.yaml: DUT — eBGP to h1 and h2 (passive), AddPath eBGP to z2.
- z1-deny-long.yaml: the same with DENY-LONG bound out toward z2.
- z1-deny-all.yaml: the same with DENY-ALL bound out toward z2.
- z2.yaml: z1's AddPath neighbor.

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Setup topology; z2 holds both paths | |
| The re-sync withdraws the non-best path the new policy denies | |
| The re-sync withdraws the remaining path under its own path-id | |
| Teardown topology | |
