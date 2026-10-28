# RIB replaces an IPv6 route in the kernel without deleting it first

## Overview

The IPv6 twin of rib_route_replace_in_place. When a protocol re-adds a
route the RIB already holds, or another route outranks the installed one,
the new route now goes into the kernel before the old one leaves. IPv6
reports a priority of 0 as 1024, so a route at 0 and one at 1024 are the
same kernel route.

z2 is the device under test. It learns 2001:db8:70::/48 from z1, then
is sent it again unchanged, sees it change next hop to z3, and sees it
outranked by a static route and handed back. A recording of z2's kernel route events
must show no deletion of the prefix through all of that, while a real
withdraw at the end is recorded as one.

## Test Topology

```
  z1 (AS65001) ── z2 (AS65002) ── z3 (AS65003)
   2001:db8::1/64  2001:db8::2/64  2001:db8::3/64
```

## Notes

All three on bridge br0; z1 and z3 originate 2001:db8:70::/48.

## Test Scenarios

| Scenario | Result |
|----------|--------|
| z2 installs 2001:db8:70::/48 from z1 | |
| the same route sent again | |
| a new next hop | |
| a static route outranks the BGP route, then hands it back | |
| none of the changes deleted the prefix from the kernel | |
| a withdraw still deletes the route, and the recording shows it | |
| Teardown topology | |
