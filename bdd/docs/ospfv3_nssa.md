# OSPFv3 NSSA (Not-So-Stubby Area) Type-7 origination and translation

## Overview

As a network operator
I want zebra-rs to support OSPFv3 NSSA areas — N-bit adjacency, Type-7
(NSSA-LSA) origination from an internal ASBR via redistribute
connected, intra-NSSA Type-7 route install, and the ABR's RFC 5340 /
RFC 3101 Type-7->Type-5 translation into the backbone — so that an IPv6
external prefix born inside an NSSA reaches both the area and the rest
of the OSPFv3 domain.
This is the IPv6 counterpart of @ospfv2_nssa. Four routers, two areas:
the backbone (0.0.0.0) holds the ABR a and a pure backbone router b;
the NSSA (0.0.0.1) hangs off a as a hub-and-spoke with the ASBR c and
the plain internal router d.

## Test Topology

```
            area 0.0.0.0 (backbone)
      b (10.0.0.2) -- 2001:db8:12::/64 -- a (ABR, 10.0.0.1)
                                          |  translator + default-originate
                                  area 0.0.0.1 (NSSA)
                     2001:db8:13::/64 |        | 2001:db8:14::/64
                       c (ASBR, 10.0.0.3)      d (10.0.0.4)
                       redistribute            plain internal
                       connected -> Type-7

    on router X the interface toward router Y is named "ethY".
    loopbacks: 2001:db8::X/128 (X = router-id last octet).
```

## Notes

The external prefix is a connected network (2001:db8:dead::/64) on a
standalone dummy interface "cust0" on c — NOT on any OSPF-enabled
interface, so it is a genuine external that enters OSPFv3 only via
`redistribute connected` as a Type-7. c is a pure ASBR (not an ABR),
so it sets the Type-7 P-bit in the prefix-options. d installs it
directly (area-scoped flood); a — the elected (sole-ABR, default
`candidate` role) translator — re-originates it as a Type-5
AS-External into the backbone, where b installs it. b carries no NSSA
link, so a translated Type-5 is the only way the prefix reaches it.

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Internal ASBR Type-7 is installed in-area and translated to Type-5 on the backbone | |
| Translator-role never keeps the Type-7 in-area and out of the backbone | |
