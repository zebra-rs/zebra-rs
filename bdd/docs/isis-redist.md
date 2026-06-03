# IS-IS redistribution of static routes into a Level-1 area

## Overview

As a network operator
I want a border router to redistribute a static route into IS-IS so a
prefix that lives outside the IS-IS domain (on a host that runs no
IS-IS) is flooded across the whole Level-1 area, installed into every
router's RIB as an external reachability, reconverges onto a backup
path when the primary link drops, and disappears again the moment the
redistribution is withdrawn.
All links are point-to-point veth pairs (network-type point-to-point)
and every "rN" router is is-type level-1 in area 49.0001. The two
edge hosts e1 and e2 do NOT run IS-IS — they are plain hosts wired to
the area by a single link and a static default route.

## Test Topology

```
    +----+      +----+      +----+      +----+      +----+
    | e1 |--10--| r1 |--10--| r2 |--10--| r3 |--10--| e2 |
    +----+      +----+      +----+      +----+      +----+
                   \                     /
                   10                  10
                     \                 /
                    +----+   10    +----+
                    | r4 |---------| r5 |
                    +----+         +----+

    loopbacks:  rI -> 10.0.0.I/32     e1 -> 10.1.1.1/32   e2 -> 10.2.2.2/32
    edges:      e1-r1 10.1.0.0/30     r3-e2 10.2.0.0/30
    spine:      r1-r2 10.0.12.0/30    r2-r3 10.0.23.0/30
    backup:     r1-r4 10.0.14.0/30    r4-r5 10.0.45.0/30   r5-r3 10.0.35.0/30
```

## Notes

There are two equal-metric-per-hop paths between r1 and r3: the short
top spine r1—r2—r3 (cost 20) and the longer bottom path
r1—r4—r5—r3 (cost 30). The top spine is the primary; the bottom path
is the backup the redistributed route falls onto when r1—r2 drops.
On router rI the interface toward rJ is named "iJ"; the interface
toward edge host eN is "ieN", and eN's interface toward its router is
"irK". e1's loopback 10.1.1.1/32 can only enter IS-IS via
redistribution: r1's edge link "ie1" carries an address but is not an
IS-IS interface. r3's edge link "ie2", by contrast, IS an IS-IS
interface so the 10.2.0.0/30 edge subnet is advertised — that gives
r1 a route back to e2's source address for the e2 -> e1 reply path.

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Build the topology and form IS-IS Level-1 adjacencies | |
| r1 redistributes e1's loopback into IS-IS and it floods across the area | |
| e2 reaches e1 end-to-end across the IS-IS domain | |
| The redistributed route reconverges onto the backup path | |
| "no redistribute" withdraws e1's loopback from r1's own LSP | |
| Teardown topology | |
