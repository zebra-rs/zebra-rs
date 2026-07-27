# OSPFv3 passive interfaces advertise their prefix without forming adjacencies

## Overview

As a network operator
I want `area <id> interface <n> passive true` on OSPFv3 to keep
advertising the interface's prefix (Intra-Area-Prefix-LSA) while
sending and accepting no Hellos — mirroring ospfv2_passive.

## Test Topology

```
    a -- 2001:db8:12::/64 -- b -- 2001:db8:23::/64 -- c
          active link           ethc PASSIVE on b     c active
```

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Passive interface prefix advertises; no adjacency forms across it | |
| Teardown topology | |
