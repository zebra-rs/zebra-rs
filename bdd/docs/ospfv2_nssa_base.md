# OSPFv2 NSSA (Not-So-Stubby Area) Type-7 origination and translation

## Overview

As a network operator
I want zebra-rs to support OSPFv2 NSSA areas — N-bit adjacency
negotiation, Type-7 (NSSA-AS-External) origination from an internal
ASBR, intra-NSSA Type-7 route install, the ABR's RFC 3101
Type-7->Type-5 translation into the rest of the OSPF domain, and a
default Type-7 injected by the ABR — so that an external prefix born
inside an NSSA is reachable both inside the area and across the
backbone, while the area still refuses to carry Type-5 AS-External.
Four routers, two areas. The backbone (0.0.0.0) holds the ABR a and
a pure backbone router b. The NSSA (0.0.0.1) hangs off a as a
hub-and-spoke: the ASBR c and the plain internal router d both peer
only with a.

## Test Topology

```
            area 0.0.0.0 (backbone)
      b (10.0.0.2) ---- 10.0.12.0/30 ---- a (ABR, 10.0.0.1)
                                          |  translator + default-originate
                                  area 0.0.0.1 (NSSA)
                       10.0.13.0/30 |        | 10.0.14.0/30
                              etha  |        |  etha
                         c (ASBR, 10.0.0.3)  d (10.0.0.4)
                         redistribute        plain internal
                         connected -> Type-7

    on router X the interface toward router Y is named "ethY".
    loopbacks: a .1  b .2  c .3  d .4  (10.0.0.X/32).
```

## Notes

The external prefix is a connected network (192.168.1.0/24) on a
standalone dummy interface "cust0" added to c AFTER zebra-rs starts.
It is NOT on any OSPF-enabled interface, so it is a genuine external
route — it enters OSPF only via c's per-area `redistribute connected`
as a Type-7. (An address on an OSPF-enabled interface would instead be
advertised as an intra-area stub and summarized as a Type-3, masking
the Type-7 path entirely.) c is a pure ASBR (not an ABR), so it sets
the Type-7 P-bit. The flood is area-scoped: d installs it directly,
and the ABR a — the elected (sole-ABR, default `candidate` role)
NSSA translator —
re-originates it as a Type-5 AS-External into the backbone, where b
installs it. b carries no NSSA link, so a Type-5 is the only way the
prefix can reach it: its presence on b is the proof the translator ran.
The metric is a flat [20] (E2 / type-2) everywhere — on d (Type-7)
and on b (translated Type-5) alike — because E2 uses the LSA metric
verbatim, independent of distance to the originator.

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Internal ASBR Type-7 is installed in-area and translated to Type-5 on the backbone | |
| Totally-NSSA suppresses Type-3 summaries but keeps the default and translation | |
| Translator-role never keeps the Type-7 in-area and out of the backbone | |
| E1 metric grows with SPF distance to the originating ASBR and the translator | |
