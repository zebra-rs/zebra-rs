# IS-IS Level-1-only over an all-point-to-point 10-router ladder

## Overview

As a network operator
I want ten zebra-rs instances arranged in a 2x5 "ladder" to form IS-IS
Level-1 adjacencies over point-to-point links, flood LSPs in a single
area, and install dual-stack (IPv4 + IPv6) routes to every loopback,
so that traffic follows the expected primary path, falls back out a
different interface when the primary link drops, and load-shares across
the two deliberate equal-cost (ECMP) diamonds.
All links are point-to-point veth pairs (network-type point-to-point);
every router is is-type level-1 in area 49.0001. On router zI the
interface toward zJ is named "iJ".

## Test Topology

```
    z1 --10-- z2 --10-- z3 --10-- z4 --10-- z5     top spine    (metric 10)
    |         |         |         |         |
    40        30        30        30        40       rungs (40 ends / 30 mid)
    |         |         |         |         |
    z6 --20-- z7 --20-- z8 --20-- z9 --20-- z10    bottom spine (metric 20)

    loopbacks: zI -> 10.0.0.I/32  and  2001:db8:0:ffff::I/128
```

## Notes

Asymmetric spines (top 10 != bottom 20) keep the topology
primary/backup everywhere except the two end columns, where the rungs
are bumped to 40 to create exactly two ECMP diamonds: z2<->z6 and
z4<->z10.

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Build the L1-only all-P2P ladder and confirm adjacencies form | |
| L1 installs reciprocal dual-stack routes to every loopback | |
| Primary path fails over to a different interface (z1 -> z5) | |
| The two deliberate ECMP diamonds resolve (z2->z6 and z4->z10) | |
| IS-IS stamps the level into the central RIB | |
| Teardown topology | |
