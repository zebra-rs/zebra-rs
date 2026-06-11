# show ipv6 nd exposes ND counters, neighbors, and BGP discovery state

## Overview

As a network operator running BGP unnumbered over IPv6 link-locals
I want `show ipv6 nd` to report per-interface RA scheduler state,
sent/received ND packet counters, and the per-source neighbor table,
and `show bgp neighbors` to report when the interface peer's
link-local was discovered via ND — so the RA exchange that underpins
peer discovery is observable instead of a black box.
This exercises the ND show pipeline end-to-end: the engine's counters
and neighbor table fill from live RA traffic, the show channel routes
`show ipv6 nd` to the ND task, and the BGP peer carries the ND
discovery timestamps stamped at materialization.

## Test Topology

```
        (i1)                                   (i1)
    ┌────┴────┐                            ┌────┴────┐
    │   z1    │────────── P2P ─────────────│   z2    │
    │ AS65001 │       fe80:: <-> fe80::    │ AS65002 │
    │ id 1.1. │                            │ id 2.2. │
    │   1.1   │                            │   2.2   │
    └─────────┘                            └─────────┘
```

## Notes

Config files mirror the @bgp_unnumbered_neighbor two-step bring-up
(base then full) so RA-enable cannot lose the race against ND's RIB
link replay; see z1-base.yaml for the rationale.
The session reaching Established proves both ends sent AND received
at least one RA (each side materializes its peer from the other's
RA), so the counter/neighbor assertions that follow are
deterministic — no fixed-delay waits are needed beyond the
session-establishment step itself.

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Setup topology | |
| ND state is visible once the unnumbered session establishes | |
| BGP neighbor detail reports the ND discovery | |
| Teardown topology | |
