# IS-IS Area Proxy (RFC 9666) — an L1 area appears as one L2 node

## Overview

As a network operator
I want an entire Level-1 area to provide Level-2 transit while appearing
to the outside backbone as a single proxy node, so that the backbone's
LSDB stays small: the area elects an Area Leader, distributes a Proxy
System ID, originates one Proxy LSP for the whole area, sources boundary
IIHs/SNPs from the proxy identity, and filters the area's own L2 LSPs at
the boundary — while inside routers still compute working routes to
destinations beyond the boundary (RFC 9666 Section 3.2 SPF rules).

All links are point-to-point veth pairs, IPv4. On router rI the
interface toward rJ is named "iJ".

## Test Topology

```
        Inside Area 49.0001 (all L1L2, area-proxy)      Outside (area 49.0002)
    ┌────────────────────────────────────────────┐   ┌─────────────────────┐
        r1 ─────────── r2 ─────────── r3 ═══════════ r4 ┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄ r5
     (candidate     (candidate     (candidate,      (L2-only)        (L2-only,
      priority 100)  priority 50)   priority 10,                      "beyond")
                                    edge: i4 is
                                    level-2-only
                                    => Outside)
    loopbacks: rI -> 10.0.0.I/32
    links:     r1-r2 10.0.12.0/30  r2-r3 10.0.23.0/30  r3-r4 10.0.34.0/30
               r4-r5 10.0.45.0/30
```

## Notes

Every inside router carries the same proxy-system-id 0000.0000.00aa and
proxy hostname "zaparea" (RFC 9666: all candidates SHOULD be
preconfigured identically so a leadership change keeps the proxy
identity stable). r3's circuit toward r4 is circuit-type level-2-only,
so it derives as an Outside Circuit without explicit marking. r5 hangs
one hop beyond the boundary router, proving both that the abstraction
propagates deeper into the backbone and that inside routers route to
destinations past the Area Proxy Boundary.

## Test Scenarios

| Scenario | Result |
|----------|--------|
| The area elects a leader, reaches readiness, and originates the Proxy LSP | |
| Outside routers see one proxy node, never the inside topology | |
| Traffic crosses the abstraction in both directions, one hop beyond included | |
| Area Leader failover regenerates the Proxy LSP from the successor | |
| Teardown topology | |
