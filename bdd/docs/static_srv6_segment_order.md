# A static SRv6 segment list is visited in the order it is written

## Overview

As a network operator
I want `segments <s1> <s2> ...` on a static route to send the packet to
s1 first, then s2, as `ip -6 route add ... encap seg6 ... segs s1,s2`
does, so that the list I configure is the path the packet takes.

The kernel takes the SRH as it goes on the wire, where the list is
stored backwards and the outer destination is read from the top index.
zebra-rs wrote the list in forwarding order, so a list of two or more
segments was visited last segment first, and `encap-type H.Encap.Red`
dropped the first segment altogether. A single segment reads the same
both ways, so one-segment routes always worked.

z1 cannot reach z3's SIDs by itself (a static blackhole covers z3's
locator), so every list below delivers only if the packet is sent to
z2's SID, the first segment, first.

## Test Topology

```
   z1 ───────────────── z2 ───────────────── z3 ─────────────── h3
      2001:db8:12::/64     2001:db8:23::/64     2001:db8:300::/64
   LOC1 fcbb:bbbb:1::/48   LOC2 fcbb:bbbb:2::/48   LOC3 fcbb:bbbb:3::/48
   blackhole fcbb:bbbb:3::/48                      End.DT6 fcbb:bbbb:3:e064::
```

## Notes

h3 is a host with 2001:db8:300::100, ::101 and ::102, one per list.

## Test Scenarios

| Scenario | Result |
|----------|--------|
| The kernel holds each list in the order written | |
| Each list delivers through its first segment | |
| Teardown topology | |
