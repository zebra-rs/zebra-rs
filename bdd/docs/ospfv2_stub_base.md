# OSPFv2 stub area drops Type-5 AS-External while keeping inter-area routes

## Overview

As a network operator
I want zebra-rs to support OSPFv2 stub areas — E-bit adjacency
negotiation, AS-External (Type-5) LSAs excluded from the area, and
inter-area Type-3 summaries still flooded in — so that a stub router
learns inter-area destinations but is shielded from the external LSDB.
Three routers, two areas. The backbone (0.0.0.0) holds the ABR a and
the ASBR b; the stub (0.0.0.1) holds the internal router c hanging
off a.

## Test Topology

```
        area 0.0.0.0 (backbone)              area 0.0.0.1 (stub)
    b (ASBR, 10.0.0.2) -- 10.0.12.0/30 -- a (ABR, 10.0.0.1) -- 10.0.13.0/30 -- c (10.0.0.3)
    redistribute connected                                                      internal
    -> Type-5

    on router X the interface toward router Y is named "ethY".
    loopbacks: a .1  b .2  c .3  (10.0.0.X/32).
```

## Notes

b redistributes a connected network (192.168.1.0/24) on a standalone
dummy interface "cust0" (NOT an OSPF interface, so it is a genuine
external — not an intra-area stub that would summarize as a Type-3) as
a Type-5 AS-External LSA. The backbone router a installs it, but
`flood_lsa_through_as` skips stub areas, so the Type-5 never reaches c
— and external prefixes are not re-advertised as Type-3 either. The
backbone loopback 10.0.0.2/32, by contrast, IS summarized into the
stub as a Type-3, so c reaches it across the area boundary.

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Stub router learns inter-area Type-3 but never the Type-5 external | |
