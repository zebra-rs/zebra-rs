# IS-IS Level-1 / Level-2 interaction across an L1 area and an L2 backbone

## Overview

As a network operator
I want a single L1/L2 router to anchor a Level-1 area on one side and the
Level-2 backbone on the other, so that it forms the right adjacency level
per circuit, maintains two independent Link State Databases, runs a
separate SPF per level, and installs both Level-1 and Level-2 routes at
the same time — while the two levels stay isolated (an L1 area's internal
prefixes do not bleed into the L2 backbone, and vice versa).
All links are point-to-point veth pairs (network-type point-to-point) and
every router is dual-stack (IPv4 + IPv6). On router rI the interface
toward rJ is named "iJ".

## Test Topology

```
        Area 49.0001  (Level-1 area)        Backbone (Level-2)   Area 49.0000
    ┌──────────────────────────────────┐  ┌──────────────────┐
                                                                  (L1, idle)
        r1 ───L1─── r2 ───L1─── r3 ════L2════ r4 ┄┄┄┄┄┄┄┄┄┄┄┄ r5
       (L1)        (L1)        (L1L2)        (L2-only)         (L1-only)
      lo .1        lo .2       lo .3          lo .4             lo .5
     49.0001      49.0001      49.0001        49.0000           49.0000

    loopbacks: rI -> 10.0.0.I/32  and  2001:db8::I/128
    links:     r1-r2 10.0.12.0/30  r2-r3 10.0.23.0/30  r3-r4 10.0.34.0/30
               r4-r5 10.0.45.0/30
               (IPv6 2001:db8:NN::/64 matching each /30)
```

## Notes

r3 is the only Level-1/Level-2 router. Its circuit toward r2 (i2) is
circuit-type level-1 (same area 49.0001 as r1/r2), and its circuit toward
r4 (i4) is circuit-type level-2-only. r3's loopback is circuit-type
level-1-2, so 10.0.0.3/2001:db8::3 is advertised into *both* the L1 LSP
(reachable from the area) and the L2 LSP (reachable from the backbone).
r5 is an L1-only router in the backbone area 49.0000, wired to r4 over a
circuit-type level-1-2 link (r4 side) — an L1L2 circuit facing a
single-level neighbor, which exercises the per-circuit P2P three-way
handshake (RFC 5303). It starts idle: while r4 is
level-2-only the r4-r5 link runs L2 only, so the L1-only r5 forms no
adjacency. The trailing scenarios promote r4 to level-1-2 (an L1 adjacency
with r5 then forms and r4's L1 LSP floods to r5) and demote it again (r4
purges that L1 LSP and r5 drops it) — exercising is-type-driven self-LSP
origination and purge end-to-end across a real adjacency.
Note on scope: zebra-rs builds each level's LSP only from prefixes whose
circuit participates at that level — there is no automatic L1->L2 leaking
and the ATT-bit / default-route mechanism is not implemented. So the L1
area's internal loopbacks (r1, r2) are NOT reachable from the L2-only r4,
and the L2-only loopback (r4) is NOT reachable from the L1-only r1. The
final scenario pins that boundary; if inter-level leaking is added later,
those two negative pings are the assertions to revisit.

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Build the topology; the border forms L1 on one side, L2 on the other | |
| The border keeps two independent Link State Databases | |
| The L1/L2 border runs a separate SPF and installs routes at both levels | |
| Forwarding is confined to each level (L1 area + L2 backbone) | |
| Levels do not leak — the L1 area and the L2 backbone stay separate | |
| Promoting the L2-only border r4 to L1/L2 originates a self-LSP at both levels | |
| r4's new L1 LSP floods to the L1-only r5 in the backbone area | |
| Demoting r4 back to level-2-only purges its L1 LSP from r5 | |
| A Level-1 adjacency is refused across the r3-r4 area boundary | |
| Teardown topology | |
