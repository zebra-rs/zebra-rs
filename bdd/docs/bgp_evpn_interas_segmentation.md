# BGP EVPN BUM tunnel segmentation — inter-AS ASBR (RFC 9572 Section 5)

## Overview

As a network operator
I want an Autonomous System Border Router to aggregate its AS's per-PE
Inclusive Multicast (Type-3) routes into a single Per-Region I-PMSI (Type-9)
route, re-originated across the AS boundary (eBGP) with next-hop-self, while
not leaking the per-AS per-PE IMET across that boundary.
This reuses the region-id segmentation machinery with "region = AS": the
ASBR's neighbor-groups carry a region-id equal to each bordered AS, so the
inter-AS (Section 5) case is the inter-region (Section 6) case applied across
an eBGP session. It exercises the eBGP egress path the all-iBGP Section 6
test never touched — AS_PATH prepend and next-hop-self at the AS boundary.
Test Topology — z1 (AS 65001 PE) and z2 (AS 65001 ASBR) are iBGP; z2 and z3
(AS 65002 ASBR) are eBGP across the AS boundary.
```
┌──────────────────────────────────────────────────────────┐
│                            br0                            │
└─────────┬─────────────────┬─────────────────┬─────────────┘
```

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Setup topology and establish the EVPN sessions | |
| The ASBR aggregates AS 65001's IMET into a Per-Region I-PMSI route | |
| AS 65002 receives the Per-Region I-PMSI across the eBGP boundary | |
| Per-AS per-PE IMET is not propagated across the AS boundary | |
| Teardown topology | |
