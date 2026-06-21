# BGP EVPN BUM tunnel segmentation — inter-region RBR (RFC 9572 Section 6)

## Overview

As a network operator
I want a Regional Border Router to aggregate a region's per-PE Inclusive
Multicast (Type-3) routes into a single Per-Region I-PMSI (Type-9) route,
re-originated into the other region with next-hop-self, while not leaking
the per-PE IMET across the region boundary.
Test Topology — three iBGP (AS 65001) speakers on a shared bridge. z2 is the
Regional Border Router; its neighbor-groups carry the region-id of each
bordered region. z1 (region A) originates a Type-3 IMET; z3 (region B) only
peers with z2.
```
┌──────────────────────────────────────────────────────────┐
│                            br0                            │
└─────────┬─────────────────┬─────────────────┬─────────────┘
```

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Setup topology and establish the EVPN sessions | |
| The RBR aggregates region A's IMET into a Per-Region I-PMSI route | |
| Region B receives the Per-Region I-PMSI with the RBR as next hop | |
| Per-PE IMET is not propagated across the region boundary | |
| Region B leaf answers the Per-Region I-PMSI with a Leaf A-D | |
| The RBR collects the region's Leaf A-D route | |
| Teardown topology | |
