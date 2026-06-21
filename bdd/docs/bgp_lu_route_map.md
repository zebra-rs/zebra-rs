# BGP per-peer route-map for IPv4 labeled-unicast (inbound + outbound)

## Overview

As a network operator
I want `neighbor X afi-safi label-v4 policy in/out <policy>` to filter
IPv4 labeled-unicast (SAFI 4) routes per neighbor, the same per-peer
per-family route-map the IPv4
unicast path already has. Before this, the labeled-unicast ingest and
advertise applied no per-neighbor policy, so BGP-LU route-maps were
silently ignored.
Policies are configured before the session establishes, so this
exercises the ingest / advertise / establish-sync policy hooks
directly.

## Test Topology

```
  ┌─────────────────┐  192.168.0.0/30  ┌─────────────────┐
  │       z1        │                  │       z2        │
  │     AS65001     ├──────────────────┤     AS65002     │
  │ label-v4 origin │   eBGP label-v4  │ label-v4 recv   │
  └─────────────────┘                  └─────────────────┘
```

## Notes

z1 originates 1.1.1.1/32, 2.2.2.2/32, 3.3.3.3/32 into BGP-LU and binds
an OUTBOUND policy OUT-LU that denies 3.3.3.3/32. z2 binds an INBOUND
policy IN-LU that denies 1.1.1.1/32.
Expected at z2: only 2.2.2.2/32 survives — 1.1.1.1/32 dropped by z2's
inbound deny, 3.3.3.3/32 never advertised by z1's outbound deny.

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Setup and verify inbound + outbound labeled-unicast route-map | |
| Teardown topology | |
