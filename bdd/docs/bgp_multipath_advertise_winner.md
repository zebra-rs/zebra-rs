# With maximum-paths above 1, a neighbor is sent the best path, not a multipath member (IPv4)

## Overview

As a network operator
I want my neighbors to receive the path `show bgp` marks best when I
install several equal-cost paths
So what I advertise matches what I report, and a change in the ECMP
member set alone does not re-advertise a different path.

Path selection returns the winner first and the multipath members after
it. The plain advertise paths took the LAST entry as "best" — a leftover
from when the selection result was a change history — so with
`maximum-paths 2` a neighbor was sent the ECMP member instead of the
winner. The FIB and VRF export already read the first entry.

## Test Topology

```
  ┌─────────────────────────────────────────────────────────┐
  │                   br0 192.168.50.0/24                   │
  └──────┬──────────────┬──────────────┬──────────────┬─────┘
    ┌────┴────┐    ┌────┴────┐    ┌────┴────┐    ┌────┴────┐
    │   h1    │    │   h2    │    │   z1    │    │   z2    │
    │scripted │    │scripted │    │  (DUT)  │    │ zebra-rs│
    │ AS65071 │    │ AS65071 │    │ AS65001 │    │ AS65072 │
    │  .2     │    │  .3     │    │  .1     │    │  .4     │
    └─────────┘    └─────────┘    └─────────┘    └─────────┘
```

## Notes

h1 and h2 run tests/scripts/bgp_attr_inject_send.py and announce
10.50.0.0/24 with the same AS_PATH ("65071") and their own next-hops, so
z1 installs both under `maximum-paths 2`. h1 tags its path with
community 65071:2, h2 with 65071:3. The paths tie down to the BGP
Identifier, so h1 (192.168.50.2) wins and h2 is the multipath member.

## Config Files

- z1.yaml: DUT — eBGP to h1 and h2 (passive) and to z2; ipv4
  maximum-paths 2.
- z2.yaml: z1's downstream eBGP neighbor.

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Setup topology and establish sessions | |
| z1 installs both paths, with h1's as the best path | |
| z2 is sent the best path, not the multipath member | |
| Teardown topology | |
