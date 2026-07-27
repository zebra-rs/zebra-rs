# OSPFv2 area ranges aggregate Type-3 summaries at the ABR

## Overview

As a network operator
I want `area <id> range <prefix>` on an ABR to fold that area's
intra-area routes into one aggregate Type-3 (RFC 2328 §12.4.3) —
or hide the whole range with `not-advertise` — so that backbone
routers carry one summary instead of every component prefix.

## Test Topology

```
       area 0.0.0.1                          area 0.0.0.0
    b (10.0.0.2) -- 10.0.12.0/30 -- a (ABR, 10.0.0.1) -- 10.0.13.0/30 -- c (10.0.0.3)
    r1 10.1.1.0/24  <- inside the      area 0.0.0.1
    r2 10.1.2.0/24  <- 10.1.0.0/16     range 10.1.0.0/16
    lo 10.0.0.2/32  <- outside the range

    on router X the interface toward router Y is named "ethY".
```

## Notes

b's dummy interfaces r1/r2 are OSPF-enabled stub prefixes inside
the range; its loopback /32 is outside. Metric check: components
cost 20 at the ABR (link 10 + stub 10), so the aggregate rides at
the largest component metric 20 and lands on c at [30].

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Components fold into one aggregate; prefixes outside the range still advertise | |
| not-advertise hides the aggregate and the components | |
| Teardown topology | |
