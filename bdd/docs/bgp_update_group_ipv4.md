# BGP Update-Group IPv4 Unicast Formation

## Overview

As a network operator I want IOS-XR-style update-groups to form
correctly: peers whose outbound advertisement signature is identical
cluster into one group, and peers whose signature differs land in
separate groups. The runtime then shares attribute transform /
outbound policy work across same-group members (Phase 2) and shares
encoded UPDATE bytes across non-source members (Phase 3).
This feature exercises grouping by **outbound policy name**, the
primary signature differentiator under operator control. Three
eBGP peers from z1: two share `out-shared`, one uses `out-different`.
Expected: `show bgp update-group` reports exactly 2 groups on z1.

## Test Topology

```
  ┌──────────────────────────────────────────────────────────────┐
  │                          br0                                 │
  └──────┬───────────────┬───────────────┬───────────────┬───────┘
         │               │               │               │
    ┌────┴────┐     ┌────┴────┐     ┌────┴────┐     ┌────┴────┐
    │   z1    │     │   z2    │     │   z3    │     │   z4    │
    │ AS65001 │     │ AS65002 │     │ AS65003 │     │ AS65004 │
    │.0.1/24  │     │.0.2/24  │     │.0.3/24  │     │.0.4/24  │
    └─────────┘     └─────────┘     └─────────┘     └─────────┘
```

## Config Files

- z1-1.yaml: AS 65001, three eBGP peers; .2 and .3 attach
- z2-1.yaml / z3-1.yaml / z4-1.yaml: simple peer back to .0.1.

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Setup 3-peer topology and establish all sessions | |
| Two peers sharing policy form one update-group; the third forms its own | |
| Group detail surfaces the negotiated capabilities | |
| Teardown topology | |
