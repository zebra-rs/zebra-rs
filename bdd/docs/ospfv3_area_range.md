# OSPFv3 area ranges aggregate Inter-Area-Prefix-LSAs at the ABR

## Overview

As a network operator
I want `area <id> range <prefix>` on an OSPFv3 ABR to fold that
area's intra-area routes into one aggregate Inter-Area-Prefix-LSA
(RFC 2328 §12.4.3 over the RFC 5340 LSA model) — or hide the whole
range with `not-advertise` — mirroring ospfv2_area_range.

## Test Topology

```
       area 0.0.0.1                            area 0.0.0.0
    b -- 2001:db8:12::/64 -- a (ABR) -- 2001:db8:13::/64 -- c
    r1 2001:db8:1:1::/64  <- inside the   area 0.0.0.1
    r2 2001:db8:1:2::/64  <- 2001:db8:1::/48 range
    lo 2001:db8::2/128    <- outside the range
```

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Components fold into one aggregate; prefixes outside the range still advertise | |
| not-advertise hides the aggregate and the components | |
| Teardown topology | |
