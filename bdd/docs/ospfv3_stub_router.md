# OSPFv3 stub-router advertisement (RFC 5340 R-bit clear)

## Overview

As a network operator
I want `max-metric router-lsa` on OSPFv3 to clear the R and V6
option bits in my Router-LSAs (ospf6d's `stub-router`) so
neighbors exclude me from transit paths (RFC 5340 §4.8.1) while my
own prefixes stay reachable — the v3 counterpart of v2's
RFC 6987 MaxLinkMetric.

## Test Topology

```
    r1 ---10--- r2 ---10--- r3   (via r2: cost 20 — normally wins)
     \---100--- r4 ---100---/    (via r4: cost 200 — the detour)
    r3-lo 2001:db8::3/128; the stub router under test is r2.
```

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Administrative R-bit clear pushes transit traffic onto the detour | |
| on-startup R-bit clear expires and the cheap path returns | |
| Teardown topology | |
