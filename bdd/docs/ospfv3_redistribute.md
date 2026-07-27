# OSPFv3 instance-level redistribute originates AS-External LSAs

## Overview

As a network operator
I want `router ospfv3 redistribute connected` and `redistribute
static` to originate AS-External (Type-5, 0x4005) LSAs for the
matching IPv6 routes — previously only `redistribute bgp` existed at
the v3 instance level — so that non-OSPF prefixes are reachable
OSPFv3-wide.

Two routers on a point-to-point link. b redistributes both a
connected prefix (a dummy interface outside OSPF) and a static
route; a must install both as external routes.

## Test Topology

```
    a (10.0.0.1) -- 2001:db8:12::/64 -- b (ASBR, 10.0.0.2)
                                        dummy cafe0 2001:db8:cafe::1/64 (not in OSPF)
                                        static 2001:db8:99::/64 -> 2001:db8:12::1
                                        redistribute connected + static

    on router X the interface toward router Y is named "ethY".
    loopbacks: a 2001:db8::1/128  b 2001:db8::2/128.
```

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Connected and static IPv6 routes appear as external routes on the neighbor | |
| Teardown topology | |
