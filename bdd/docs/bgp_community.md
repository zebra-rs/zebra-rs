# BGP well-known community handling (no-export, no-advertise)

## Overview

As a network operator
I want to verify that the well-known communities NO_EXPORT and
NO_ADVERTISE are honoured when re-advertising routes across eBGP
and iBGP sessions, using a four-router topology.

## Test Topology

```
  ┌────────────────────────────────────────────────────────────────────────┐
  │                                  br0                                   │
  └────────┬──────────────────┬──────────────────┬──────────────────┬─────┘
           │                  │                  │                  │
      ┌────┴────┐        ┌────┴────┐        ┌────┴────┐        ┌────┴────┐
      │   z1    │  eBGP  │   z2    │  iBGP  │   z3    │        │   z4    │
      │  (A)    │◀──────▶│  (B)    │◀──────▶│  (C)    │        │  (D)    │
      │ AS65001 │        │ AS65002 │        │ AS65002 │        │ AS65003 │
      │192.168. │        │192.168. │        │192.168. │        │192.168. │
      │  0.1/24 │        │  0.2/24 │        │  0.3/24 │        │  0.4/24 │
      └─────────┘        └────┬────┘        └─────────┘        └────┬────┘
                              │                eBGP                 │
                              └─────────────────────────────────────┘
```

## Notes

B has an iBGP peer (C, same AS) and an eBGP peer (D, AS65003), so a
route from A exercises both re-advertisement edges:
- NO_EXPORT: B keeps advertising to C (iBGP) but must NOT export to
  D (eBGP) — RFC 1997.
- NO_ADVERTISE: B must advertise to neither C nor D.

## Config Files

- z1-1.yaml: A baseline — eBGP peer to B, no network advertised.
- z1-2.yaml: A advertises 1.1.1.1/32 with no community attribute.
- z1-3.yaml: A advertises 1.1.1.1/32 with community "no-export".
- z1-4.yaml: A advertises 1.1.1.1/32 with community "no-advertise".
- z1-5.yaml: A advertises 1.1.1.1/32 through a permit-all policy
- z2-1.yaml: B — eBGP to A, iBGP to C, eBGP to D.
- z3-1.yaml: C — iBGP to B only.
- z4-1.yaml: D — eBGP to B only.
- eBGP MinRouteAdvertisementInterval = 30 s
- iBGP MinRouteAdvertisementInterval =  5 s
- End-to-end A → B → C propagation: up to 30 + 5 = 35 s.
- End-to-end A → B → D propagation: up to 30 + 30 = 60 s.
- Each scenario that triggers a fresh advertisement on A waits

Convergence wait-time rationale:

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Setup topology and establish BGP sessions | |
| A advertises 1.1.1.1/32 with no community — C and D receive it | |
| A re-advertises 1.1.1.1/32 with community no-export — C still receives it, D does NOT | |
| A re-advertises 1.1.1.1/32 with community no-advertise — neither C nor D receives it | |
| A reverts to a community-free advertisement — C and D receive it again | |
| Teardown topology | |
