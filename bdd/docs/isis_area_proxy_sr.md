# IS-IS Area Proxy with Segment Routing (RFC 9666 SR merges and Area SID)

## Overview

As a network operator
I want an Area-Proxy area running SR-MPLS to present a coherent Segment
Routing view to the backbone: the Proxy LSP advertises the area's merged
SRGB (identical starting values required, minimum range) and carries the
inside prefixes' Prefix-SIDs (P-Flag set, E-Flag reset), plus an anycast
Area SID that every Inside Edge Router terminates with a label pop — so
an outside router can steer SR traffic to inside destinations, and to
"any edge of the area", straight through the abstraction.

All links are point-to-point veth pairs, IPv4, SR-MPLS everywhere with
the default SRGB (16000 + index). On router rI the interface toward rJ
is named "iJ".

## Test Topology

```
      Inside Area 49.0001 (L1L2, area-proxy)      Outside (area 49.0002)
    ┌──────────────────────────────────────┐   ┌──────────────────┐
        r1 ──────────────── r2 ═══════════════ r3
     (candidate 100,     (candidate 50,      (L2-only,
      lo SID index 100)   edge, lo index      lo index 300)
                          200)
    loopbacks: rI -> 10.0.0.I/32
    links:     r1-r2 10.0.12.0/30   r2-r3 10.0.23.0/30
    Area SID:  10.0.0.100/32 index 500 (candidates r1 and r2)
```

## Test Scenarios

| Scenario | Result |
|----------|--------|
| The Proxy LSP carries the merged SRGB, copied Prefix-SIDs, and the Area SID | |
| An outside router steers SR-MPLS traffic through the abstraction | |
| Teardown topology | |
