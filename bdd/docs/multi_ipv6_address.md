# Multiple IPv6 addresses per interface

## Overview

As a network operator
I want to configure several IPv6 addresses on one interface
So that the daemon mirrors the kernel's per-address model — one
connected route per subnet that survives partial deletes, DAD state
captured and cleared in place — while OSPFv3 and IS-IS advertise
subnets (masked, deduped) instead of addresses, address changes
reach peers immediately, and a link-local renumber recovers.

## Test Topology

```
  ┌────────────────────────────────────────┐
  │                  br0                   │
  └────────────┬───────────────┬───────────┘
               │               │
    2001:db8:1::1/64        2001:db8:1::9/64
    2001:db8:1::11/64          (vz2ns)
    2001:db8:2::1/64
            (vz1ns)
          ┌────┴────┐     ┌────┴────┐
          │   z1    │     │   z2    │
          └─────────┘     └─────────┘
```

## Config Files

- z1.yaml: three addresses on vz1ns; OSPFv3 area 0 + IS-IS L2 on it
- z2.yaml: one address on vz2ns; same protocols, DR priority 0 so
  z1 is always the DR (the DR's aggregated prefixes are not
  FIB-routable on the DR itself)

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Setup topology and the kernel address model is mirrored | |
| Protocols advertise subnets once, masked, and forwarding works | |
| Deleting one same-subnet address keeps the connected route and the advertisement | |
| Address add and delete reach the peer immediately | |
| A link-local renumber on z1 is followed by z2 | |
| Teardown topology | |
