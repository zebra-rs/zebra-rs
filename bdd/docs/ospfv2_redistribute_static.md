# OSPFv2 instance-level redistribute static originates Type-5 AS-External LSAs

## Overview

As a network operator
I want `router ospf redistribute static` to originate a Type-5
AS-External LSA for every static route in the RIB — with the E-bit
set in the Router-LSA so the domain computes paths to the ASBR — so
that statically routed prefixes are reachable OSPF-wide without
per-area configuration.
Two routers on a point-to-point link. b carries a static route and
redistributes it; a must install the prefix as an external route.

## Test Topology

```
    a (10.0.0.1) -- 10.0.12.0/30 -- b (ASBR, 10.0.0.2)
                                    static 192.168.50.0/24 -> 10.0.12.1
                                    redistribute static -> Type-5

    on router X the interface toward router Y is named "ethY".
    loopbacks: a .1  b .2  (10.0.0.X/32).
```

## Notes

The static route's nexthop deliberately points back across the OSPF
link (it resolves via the connected /30), so the route is installed
in b's RIB and delivered to OSPF through the RIB redistribution
subscription — the same path any real static route takes.

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Static route appears as an external route on the neighbor | |
| Teardown topology | |
