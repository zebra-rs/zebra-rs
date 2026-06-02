# BGP well-known community handling (no-export, no-advertise)

## Overview

As a network operator
I want to verify that the well-known communities NO_EXPORT and
NO_ADVERTISE are honoured when re-advertising routes across eBGP
and iBGP sessions, using a three-router topology.

## Test Topology

```
  ┌──────────────────────────────────────────────────────────┐
  │                          br0                             │
  └─────────┬──────────────────┬──────────────────┬──────────┘
            │                  │                  │
       ┌────┴────┐        ┌────┴────┐        ┌────┴────┐
       │   z1    │  eBGP  │   z2    │  iBGP  │   z3    │
       │  (A)    │◀──────▶│  (B)    │◀──────▶│  (C)    │
       │ AS65001 │        │ AS65002 │        │ AS65002 │
       │192.168. │        │192.168. │        │192.168. │
       │  0.1/24 │        │  0.2/24 │        │  0.3/24 │
       └─────────┘        └─────────┘        └─────────┘
```

## Config Files

- z1-1.yaml: A baseline — eBGP peer to B, no network advertised.
- z1-2.yaml: A advertises 1.1.1.1/32 with no community attribute.
- z1-3.yaml: A advertises 1.1.1.1/32 with community "no-export".
- z1-4.yaml: A advertises 1.1.1.1/32 with community "no-advertise".
- z2-1.yaml: B — eBGP to A, iBGP to C.
- z3-1.yaml: C — iBGP to B only.
- eBGP MinRouteAdvertisementInterval = 30 s
- iBGP MinRouteAdvertisementInterval =  5 s
- End-to-end A → B → C propagation: up to 30 + 5 = 35 s.
- Each scenario that triggers a fresh advertisement on A waits

Convergence wait-time rationale:

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Setup topology and establish BGP sessions | |
| A advertises 1.1.1.1/32 with no community — C receives it | |
| A re-advertises 1.1.1.1/32 with community no-export — C still receives it | |
| A re-advertises 1.1.1.1/32 with community no-advertise — C does NOT receive it | |
| A reverts to plain advertisement — C receives it again | |
| Teardown topology | |
