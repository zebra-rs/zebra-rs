# Multiple IPv4 addresses per interface with kernel secondary flag

## Overview

As a network operator
I want to configure several IPv4 addresses on one interface
So that same-subnet duplicates carry the kernel's IFA_F_SECONDARY
verdict — no config keyword — while routing protocols keep treating
the interface as one link per subnet: the connected route survives a
secondary's removal, advertisements count subnets not addresses, and
nexthops/endpoints always use the primary.

## Test Topology

```
  ┌────────────────────────────────────────┐
  │                  br0                   │
  └────────────┬───────────────┬───────────┘
               │               │
      10.0.1.1/24 (primary)  10.0.1.9/24
      10.0.1.2/24 (secondary)  (vz2ns)
      10.2.0.1/24 (primary)
            (vz1ns)
          ┌────┴────┐     ┌────┴────┐
          │   z1    │     │   z2    │
          └─────────┘     └─────────┘
```

## Config Files

- z1.yaml: three addresses on vz1ns; OSPFv2 area 0 + IS-IS L2 on it
- z2.yaml: one address on vz2ns; same protocols

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Setup topology and the kernel computes the secondary verdict | |
| Protocols advertise subnets once and pick the primary as nexthop | |
| Deleting the secondary keeps the connected route and the advertisement | |
| Deleting the primary hands the subnet to the configured sibling | |
| Teardown topology | |
