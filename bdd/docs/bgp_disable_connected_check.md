# BGP disable-connected-check (eBGP connected-network check)

## Overview

As a network operator
I want a single-hop eBGP session over loopback addresses to be held down
by default (the neighbor is not on a directly-connected subnet) and to
come up once `disable-connected-check` is set, confirming both the check
and its override end-to-end.

## Test Topology

```
  ┌─────────────────────────────────────────┐
  │                   br0                    │
  └─────────────┬───────────────┬───────────┘
                │               │
           ┌────┴────┐     ┌────┴────┐
           │   z1    │     │   z2    │
           │ AS65001 │     │ AS65002 │
           │ 10.0.0. │     │ 10.0.0. │
           │  1/24   │     │  2/24   │
           │ lo .255 │     │ lo .255 │
           │  .0.1/32│     │  .0.2/32│
           └─────────┘     └─────────┘
```

## Notes

z1 and z2 are directly connected at layer 2 over br0 (10.0.0.0/24), but
peer eBGP using their loopbacks (10.255.0.1 ↔ 10.255.0.2), each reachable
only via a static route — so neither peering address is on a connected
subnet. A TTL-1 packet still reaches the L2-adjacent peer, so the only
thing standing between the two routers is the connected check.

## Config Files

- z{1,2}-base.yaml: loopback peering, no disable-connected-check.
- z{1,2}-disable.yaml: same, plus `disable-connected-check`.

## Test Scenarios

| Scenario | Result |
|----------|--------|
| The connected check holds a loopback eBGP session down | |
| disable-connected-check brings the loopback eBGP session up | |
| Teardown topology | |
