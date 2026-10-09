# IS-IS keeps a moved Prefix-SID's old label forwarding for a while

## Overview

As a network operator
I want a Prefix-SID that an SRGB change moves to a new label to keep
its old label forwarding for a while, on every router, so that a
neighbour still sending the old label (it has not processed the new
advertisement yet) is not dropped
(docs/design/mpls-label-allocation.md §6.1).

A Prefix-SID's label is its originator's SRGB start plus the index.
r3 moves its SRGB from 16000 to 18000, so its index 3 moves from label
16003 to 18003: on r3 (its own pop entry), on r2 (the penultimate hop,
a pop) and on r1 (a swap toward r2). Each installs 18003 at once and
keeps 16003 for the hold, 60 s, then withdraws it.

## Test Topology

```
   r1 ──────────── r2 ──────────── r3
     10.0.12.0/24     10.0.23.0/24
   lo 10.0.0.1/2/3, Prefix-SID index 1/2/3
```

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Build the chain on the default SRGB | |
| The moved Prefix-SID's old label forwards for the hold, then goes | |
| Teardown | |
