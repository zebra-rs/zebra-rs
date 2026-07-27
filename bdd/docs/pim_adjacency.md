# PIM-SM two-router neighborship forms on a point-to-point link

## Overview

As a network operator
I want two zebra-rs PIM routers joined by a veth link to discover
each other through Hellos and elect the Designated Router, so the
PIM-SM neighbor plane (Hello options, holdtime, DR priority) is
exercised router-to-router.
p1 advertises DR priority 200, p2 the default-equivalent 1. With
priority-based election the LOWER address 10.1.12.1 must win DR —
proving the election used the DR-Priority option and not the
highest-address fallback.

## Test Topology

```
    p1 (10.1.12.1/24, DR prio 200) --- veth --- p2 (10.1.12.2/24, DR prio 1)
       eth1                                        eth2
```

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Two PIM routers discover each other and elect the DR | |
| Teardown topology | |
