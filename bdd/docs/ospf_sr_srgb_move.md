# OSPFv2 and OSPFv3 keep a moved Prefix-SID's old label forwarding for a while

## Overview

As a network operator
I want a Prefix-SID that an SRGB change moves to a new label to keep
its old label forwarding for a while, on every router and in both
OSPF versions, so that a neighbour still sending the old label (it has
not processed the new advertisement yet) is not dropped
(docs/design/mpls-label-allocation.md §6.1).

A Prefix-SID's label is its originator's SRGB start plus the index.
The chain runs OSPFv2 over IPv4 and OSPFv3 over IPv6, both with
SR-MPLS. r3 moves its SRGB from 16000 to 18000: its OSPFv2 index 3
moves from label 16003 to 18003 and its OSPFv3 index 13 from 16013 to
18013, on r3 and on the routers forwarding toward it. Each installs
the new label at once and keeps the old one for the hold, 60 s.

## Test Topology

```
   r1 ──────────── r2 ──────────── r3
     10.0.12.0/24     10.0.23.0/24
     2001:db8:12::/64 2001:db8:23::/64
   lo 10.0.0.1/2/3 (OSPFv2 SID index 1/2/3)
      2001:db8::1/2/3 (OSPFv3 SID index 11/12/13)
```

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Build the dual-stack chain on the default SRGB | |
| The moved Prefix-SIDs' old labels forward for the hold, then go | |
| Teardown | |
