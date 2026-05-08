# IS-IS SRv6 end-to-end with H.Encap and End.DT6

## Overview

As a network operator
I want a 4-router IS-IS L2 chain to converge with SRv6 locators,
so a static IPv6 route at the head encapsulates traffic into a
uSID, the transit nodes forward by SRv6, and the tail decapsulates
via End.DT6 — letting Z1 reach a destination behind Z4 that is not
in any IGP.

## Test Topology

```
  ┌────────┐  enp0s6 ── enp0s6  ┌────────┐  enp0s7 ── enp0s6  ┌────────┐  enp0s7 ── enp0s7  ┌────────┐
  │   z1   │────────────────────│   z2   │────────────────────│   z3   │────────────────────│   z4   │
  │ uN /48 │                    │ uN /48 │                    │ uD /48 │                    │ stub   │
  │ fcbb:1 │                    │ fcbb:2 │                    │ fcbb:3 │                    │        │
  └────────┘                    └────────┘                    └────────┘                    └────────┘
   2001:db8:ff00:10::1/64       :10::2/64    :2::1/64          :2::2/64    :5::1/64           :5::2/64
   (z1 enp0s6)                  (z2 enp0s6)  (z2 enp0s7)       (z3 enp0s6) (z3 enp0s7)        (z4 enp0s7)
```

## Notes

- z1, z2, z3 run IS-IS L2; z4 is a stub reached via a static
  default route towards z3's enp0s7.
- z2 advertises locator `LOC_uN1` (fcbb:bbbb:2::/48); z3 advertises
  `LOC_uD` (fcbb:bbbb:3::/48). z3 has a static `End.DT6` SID at
  `fcbb:bbbb:3:fe00::/128`.
- z1 has a static IPv6 route to `2001:db8:ff00:5::/64` whose
  nexthop is `segments fcbb:bbbb:3:fe00::` — H.Encap into uSID at
  z1, transit through z2, decap on z3 via End.DT6, then plain
  IPv6 forwarding to z4.

## Config Files

- z1.conf, z2.conf, z3.conf, z4.conf

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Setup the SRv6 chain and ping the far end through the SID | |
