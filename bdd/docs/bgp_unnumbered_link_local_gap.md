# An unnumbered neighbor gets the routes it missed while our link-local was gone

## Overview

As a network operator running BGP over IPv6-only point-to-point links
I want a route announced while our link-local on the link is unknown to
reach the unnumbered neighbor once the link-local is back
So the neighbor never misses a route over a short address flap.

IPv4 routes reach an unnumbered neighbor with our IPv6 link-local on
the link as the next-hop (RFC 8950). While BGP knew no such address the
update-group flush skipped the neighbor — but the route was already
recorded as sent, and the address coming back only updated the address
table: the neighbor never got the route until it changed again. The
extended next-hop is IPv4-unicast only, so there is no IPv6 twin.

## Test Topology

```
    ┌─────────┐                            ┌─────────┐
    │   z1    │────────── P2P ─────────────│   z2    │
    │ AS65001 │  fe80::1 <-> fe80::(auto)  │ AS65002 │
    └─────────┘                            └─────────┘
```

## Notes

z1's link-local on i1 is pinned to fe80::1 before zebra-rs starts, so the
feature can delete it and add the same address back while the session
stays up (a few seconds, well inside the hold time).

## Config Files

- z1-base.yaml / z2-base.yaml: a bare `router bgp` block (two-step
  bring-up, as in bgp_unnumbered_neighbor).
- z1-full.yaml / z2-full.yaml: RA on i1, the interface-keyed neighbor, a
  one-second advertisement interval, one IPv4 network each.

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Setup; the unnumbered session exchanges IPv4 routes | |
| A route announced while z1's link-local is gone reaches z2 once it is back | |
| The session rode out the gap | |
| Teardown topology | |
