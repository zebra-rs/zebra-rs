# OSPFv2 multi-area routing across two Area Border Routers

## Overview

As a network operator
I want zebra-rs to act as an OSPFv2 Area Border Router — originating a
per-area Router-LSA and Type-3 Summary-LSAs — so that hosts in different
non-backbone areas learn each other's prefixes through the backbone and
are mutually reachable, with paths chosen by configured interface cost.
Six routers in three areas. The backbone (area 0.0.0.0) holds a, b, c, d
fully meshed-ish; a and c are the ABRs, each anchoring one non-backbone
area. Area 0.0.0.1 hangs off a (internal router e); area 0.0.0.2 hangs
off c (internal router f).

## Test Topology

```
                 area 0.0.0.1                 area 0.0.0.2
                  e (10.0.0.5)                 f (10.0.0.6)
                     |                            |
                10.0.15.0/30                 10.0.36.0/30
                     | ethe                  ethf |
        ____________ a (ABR, 10.0.0.1) ........  c (ABR, 10.0.0.3) ____
       |   area 0   /|                            |\   area 0          |
       |           / |                            | \                  |
   10.0.12.0/30   /  10.0.14.0/30 (cost 20)       |  10.0.23.0/30      |
   (cost 10)     /   |                            |  (cost 10)         |
       |        /    | etha                  ethd | 10.0.34.0/30       |
       b (10.0.0.2)  d (10.0.0.4) ________________/  (cost 20)         |
       |  \________ 10.0.24.0/30 (cost 10) ________/                   |
       |              (b - d)                                          |
       \______________________________________________________________/

    backbone links + cost:
      a-b 10.0.12.0/30  cost 10      a-d 10.0.14.0/30  cost 20
      b-c 10.0.23.0/30  cost 10      c-d 10.0.34.0/30  cost 20
      b-d 10.0.24.0/30  cost 10
    on router X the interface toward router Y is named "ethY".
    loopbacks: a .1  b .2  c .3  d .4  e .5  f .6  (10.0.0.X/32).
```

## Notes

The cost-20 a-d and c-d links are the only non-default metrics. They are
always tied (20) with the two-hop alternative (a-b-d = c-b-d = 10+10), so
the direct link only ever shows up as an equal-cost path at metric 20 —
had cost stayed at the default 10 the direct link would win outright at
10. That metric is the deterministic proof the configured cost took
effect.
Inter-area reachability between e (area 1) and f (area 2) is the headline:
it can only work if a and c each originate Type-3 summaries — a's of
area 1 into the backbone, c re-advertising them into area 2, and the
mirror image for f — so the ABR producer is exercised end to end.

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Two ABRs glue three areas; inter-area routes form and resolve by cost | |
