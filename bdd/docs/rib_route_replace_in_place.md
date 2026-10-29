# RIB replaces a route in the kernel without deleting it first

## Overview

When a protocol re-adds a route the RIB already holds, or another route
outranks the installed one, the RIB used to delete the installed route
from the kernel and then add the new one, so the prefix had no route in
between. That happened on every change of the route, even one that
leaves forwarding as it was, such as a neighbor sending the same route
again.

Now the new route goes in first. Its install replaces the kernel route
at the same priority in place (NLM_F_REPLACE), and only the old route's
routes at other priorities are deleted after it. FPM and cradle key a
route by prefix, so the new route's tee overwrites the old one there.

z2 is the device under test. It learns 10.70.1.0/24 from z1, then is
sent it again unchanged, sees it change next hop to z3, and sees it
outranked by a static route and handed back, all at kernel priority 0. A recording of
z2's kernel route events must show no deletion of the prefix through
all of that, while a real withdraw at the end is recorded as one.

## Test Topology

```
  z1 (AS65001) ── z2 (AS65002) ── z3 (AS65003)
   10.0.0.1/24    10.0.0.2/24     10.0.0.3/24
```

## Notes

All three on bridge br0; z1 and z3 originate 10.70.1.0/24.

## Test Scenarios

| Scenario | Result |
|----------|--------|
| z2 installs 10.70.1.0/24 from z1 | |
| the same route sent again | |
| a new next hop | |
| a static route outranks the BGP route, then hands it back | |
| none of the changes deleted the prefix from the kernel | |
| a withdraw still deletes the route, and the recording shows it | |
| Teardown topology | |
