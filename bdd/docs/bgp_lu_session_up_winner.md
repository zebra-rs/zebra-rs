# A labeled-unicast neighbor that comes up late is dumped the best path (IPv4)

## Overview

As a network operator
I want a labeled-unicast neighbor that establishes after my routes are
in to receive each prefix's best path and label
So a late session does not start out forwarding on a worse path until
the next change for the prefix happens to correct it.

Labeled-unicast is not update-group batched: a neighbor that comes up
gets the Loc-RIB through a session-up dump. For a plain (non-AddPath)
neighbor the dump took the LAST row of the prefix's candidate list —
the path added or refreshed most recently — rather than the selected
best path. The unicast and VPN dumps read the selected path.

## Test Topology

```
  ┌──────────────────────────────────────────────────────────────┐
  │                     br0 192.168.52.0/24                      │
  └──────┬───────────────┬───────────────┬───────────────┬───────┘
    ┌────┴────┐     ┌────┴────┐     ┌────┴────┐     ┌────┴────┐
    │   z2    │     │   z3    │     │   z1    │     │   z4    │
    │ AS65002 │     │ AS65002 │     │  (DUT)  │     │ AS65100 │
    │  .2     │     │  .3     │     │ AS65100 │     │  .4     │
    │lo1 10.52│     │lo1 10.52│     │  .1     │     │ (late)  │
    └─────────┘     └─────────┘     └─────────┘     └─────────┘
```

## Notes

z2 and z3 both originate 10.52.0.1/32 into IPv4 labeled-unicast. The
two paths tie down to the BGP Identifier, so z2's (192.168.52.2) is
z1's best. z3's path arrives second and is the newest candidate. z4, a
plain iBGP labeled-unicast neighbor, starts only after that; z1 relays
the prefix to it with the next-hop unchanged, so z4's next-hop names
the path it was sent.

## Config Files

- z1.yaml: DUT — label-v4 eBGP to z2 and z3, iBGP to z4.
- z2.yaml, z3.yaml: originate 10.52.0.1/32.
- z4.yaml: the late iBGP neighbor.

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Setup topology; z1 learns z2's path, then z3's | |
| The late neighbor is dumped the best path, not the newest candidate | |
| Teardown topology | |
