# clear ospf neighbor resets an OSPFv2 adjacency

## Overview

As a network operator
I want `clear ospf neighbor [<router-id>]` to tear an OSPFv2
adjacency down so it re-forms from scratch — exactly like a
dead-timer timeout — so I can force a fresh database exchange on
demand without restarting the daemon.
Two zebra-rs routers, o1 and o2, are joined by one point-to-point
link and each advertise a /32 loopback into area 0.0.0.0. Once the
adjacency is Full and the loopbacks are mutually reachable, clearing
the neighbor must drop and rebuild the adjacency. The neighbor's
up-time resetting is the deterministic proof that the instance was
destroyed and re-learned rather than left untouched: had the clear
been a no-op the up-time would keep climbing past the wait budget.

## Test Topology

```
    o1 (10.0.0.1) --- 10.0.12.0/30 --- o2 (10.0.0.2)
       eth1  point-to-point  eth2
```

## Test Scenarios

| Scenario | Result |
|----------|--------|
| clear ospf neighbor destroys and re-forms the adjacency | |
