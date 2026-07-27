# OSPFv3 ABR originates Inter-Area-Prefix-LSAs across three areas

## Overview

As a network operator
I want a zebra-rs OSPFv3 Area Border Router to condense each area's
routes into Inter-Area-Prefix-LSAs (0x2003) flooded into its other
areas — with backbone split-horizon and per-area SPF — so that
routers in different non-backbone areas reach each other through
the backbone. Mirrors ospfv2_multi_area for the v3 LSA model.

## Test Topology

```
                 area 0.0.0.1                 area 0.0.0.2
                  e (2001:db8::5)              f (2001:db8::6)
                     |                            |
              2001:db8:15::/64             2001:db8:36::/64
                     | ethe                  ethf |
        ____________ a (ABR, 10.0.0.1) ........  c (ABR, 10.0.0.3) ____
       |   area 0   /|                            |\   area 0          |
   2001:db8:12::/64 /2001:db8:14::/64 (cost 20)   | 2001:db8:23::/64   |
       |           /  | etha                 ethd | 2001:db8:34::/64   |
       b (2001:db8::2) d (2001:db8::4) ___________/  (cost 20)         |
       |  \________ 2001:db8:24::/64 (b - d) ______/                   |
       \_______________________________________________________________|

    on router X the interface toward router Y is named "ethY".
    loopbacks: 2001:db8::X/128, router-ids 10.0.0.X (a=1 .. f=6).
```

## Notes

The cost-20 a-d and c-d links tie the two-hop alternative (a-b-d =
c-b-d = 10+10), so d's loopback shows at metric 20 from a and c —
with the default cost 10 the direct link would win at metric 10,
making "metric 20" the deterministic proof the configured cost took.

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Routers in two non-backbone areas reach each other through the backbone | |
| Teardown topology | |
