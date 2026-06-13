# BGP AddPath Send for IPv4 unicast (RFC 7911)

## Overview

As a network operator
I want a BGP speaker with two paths for one prefix to advertise BOTH
of them — each carrying its own path identifier — to a neighbor that
negotiated AddPath, instead of the single best path.
This is the first end-to-end AddPath wire test in the suite: it
exercises the per-candidate advertise twin
(`route_advertise_to_addpath`), the AddPath-Send membership split,
and the path-id stamping. The same shape validates the VPNv6 / EVPN /
labeled-unicast twins as those land.

## Test Topology

```
        10.10.10.0/24          10.10.10.0/24
       (origin AS65001)       (origin AS65002)
            z1 ──┐               ┌── z2
       192.168.   │   192.168.   │   192.168.
        0.1/24    └──→  0.3/24  ←─┘    0.2/24
                       z3 (AS65003)
                        │  add-path send-receive
                        ↓
                       z4 (AS65004)  192.168.0.4/24
```

## Notes

z3 learns 10.10.10.0/24 over eBGP from BOTH z1 (AS_PATH 65001) and
z2 (AS_PATH 65002), so its Loc-RIB holds two candidate paths. With
AddPath Send negotiated toward z4, z3 advertises both — so z4 sees
TWO available paths for the prefix, not just the best one.

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Setup topology and establish sessions | |
| The AddPath receiver sees both paths for the prefix | |
| Teardown topology | |
