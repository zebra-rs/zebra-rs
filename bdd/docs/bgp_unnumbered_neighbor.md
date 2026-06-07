# BGP IPv6 unnumbered neighbor discovered via Router Advertisements

## Overview

As a network operator running BGP over IPv6-only point-to-point links
I want a peer keyed by its outbound interface (no configured remote
address) to be discovered from the neighbour's Router Advertisement,
establish a session over the link-local, and carry IPv4 routes via
RFC 8950 Extended Next Hop Encoding.
This exercises the full unnumbered path end-to-end through the
YAML/YANG/CLI stack — ND RA send + receive, NeighborDiscovered →
interface-keyed Peer materialization, the active-connect over
fe80::%ifindex AND the passive accept that binds an inbound
link-local connection back to its interface-keyed peer (both ends
connect actively and accept passively, so a collision must resolve
into a single Established session), and ENHE-carried IPv4 routes.

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

## Config Files

- z1-base.yaml / z2-base.yaml: a bare `router bgp` block — spawns ND
- z1-full.yaml / z2-full.yaml: enable `send-advertisements` on i1,

Note: the interface-keyed peer's remote address is a kernel-assigned
link-local that the scenario can't name, so the session is asserted
with the address-agnostic "BGP session in namespace … should
eventually be …" step (it reads `show ip bgp neighbors`, which lists
interface-keyed peers).

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Setup topology | |
| RA discovery establishes the unnumbered session and exchanges IPv4 routes | |
| Removing the interface-neighbor tears the session down | |
| Teardown topology | |
