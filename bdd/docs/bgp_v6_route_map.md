# BGP per-peer route-map for IPv6 unicast (inbound + outbound)

## Overview

As a network operator
I want `neighbor X afi-safi ipv6 policy in/out <policy>` to filter and
rewrite IPv6 unicast routes per neighbor — the same per-peer per-family
route-map semantics
the IPv4 unicast path already has. Before this, the v6 ingest and the
v6 advertise applied no per-neighbor policy, so v6 route-maps were
silently ignored (the global `table-map` was the only v6 policy hook).
Unlike `table-map` (which gates only the kernel install and keeps a
denied route visible in `show bgp ipv6`), an inbound route-map deny
drops the route from the receiver's RIB entirely, and an outbound deny
suppresses the advertisement at the originator.
Policies are configured before the session establishes, so the test
exercises the ingest / advertise policy hooks directly (no inbound
soft-reconfiguration is assumed).

## Test Topology

```
  ┌─────────────────┐   192.168.0.0/30    ┌─────────────────┐
  │       z1        │   2001:db8:12::/64   │       z2        │
  │     AS65001     ├─────────────────────┤     AS65002     │
  │ .1 / 12::1      │                     │ .2 / 12::2      │
  └─────────────────┘                     └─────────────────┘
```

## Notes

z1 originates 2001:db8:100::/48, :200::/48, :300::/48 and binds an
OUTBOUND policy OUT6 that denies :300::/48. z2 binds an INBOUND policy
IN6 that denies :100::/48 and stamps `set med 50` on :200::/48.
Expected at z2: only :200::/48 survives — :100::/48 is dropped by z2's
inbound deny, :300::/48 is never advertised by z1's outbound deny —
and :200::/48 carries the inbound-stamped MED into the FIB.

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Setup topology and verify inbound + outbound IPv6 route-map | |
| Teardown topology | |
