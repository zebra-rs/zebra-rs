# OSPFv2 virtual links connect a remote ABR to the backbone

## Overview

As a network operator
I want `area <transit-id> virtual-link <router-id>` (RFC 2328 §15)
to form a logical backbone adjacency between two ABRs across a
non-backbone transit area — so an area with no physical backbone
connection (area 2 below) still exchanges inter-area routes with
area 0.

## Test Topology

```
     area 0        area 0.0.0.1 (transit)      area 0.0.0.2
    lo 10.0.0.1   r1 -- 10.0.12.0/30 -- r2 -- 10.0.23.0/30 -- r3
                   \____ virtual-link ____/     lo 10.0.0.3
    r2 has NO physical area-0 interface; without the VL, r2 is not
    backbone-attached and area 2 never learns 10.0.0.1/32.
```

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Virtual link forms and carries inter-area routes end to end | |
| Multi-hop transit — the ABRs are two hops apart through the transit area | |
| Virtual link with MD5 authentication forms and carries routes | |
| Teardown topology | |
