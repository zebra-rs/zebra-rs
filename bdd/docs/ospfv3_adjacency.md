# OSPFv3 two-router adjacency forms over a point-to-point link

## Overview

As a network operator
I want two zebra-rs OSPFv3 routers joined by a point-to-point link to
progress all the way to Full and synchronise their databases, so the
OSPFv3 control plane is exercised router-to-router (not only against
an external implementation).
This is the v3 counterpart of `ospf_clear_neighbor` and guards the
OSPFv3 half of the adjacency-formation fixes (Router-ID config applied
per instance, `addr_add` re-firing InterfaceUp, and the DB-exchange
More-bit being cleared). Without those, two zebra-rs v3 routers share
the default Router-ID 10.0.0.1 and/or stall in Exchange and never reach
Full — a regression invisible to zebra-rs<->FRR validation and to CI
(which does not run the BDD suite).
Reaching Full in BOTH directions is the proof: it requires the master
(higher Router-ID, o2) and the slave (o1) to complete ExStart ->
Exchange -> Loading -> Full, which only happens when all three fixes
hold.

## Test Topology

```
    o1 (router-id 10.0.0.1) --- 2001:db8:12::/64 --- o2 (router-id 10.0.0.2)
       eth1   point-to-point, area 0.0.0.0   eth2
    loopbacks: 2001:db8::1/128 (o1)         2001:db8::2/128 (o2)
```

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Two OSPFv3 routers reach Full over a point-to-point link | |
