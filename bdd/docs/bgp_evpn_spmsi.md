# BGP EVPN BUM segmentation — selective S-PMSI (RFC 9572 Type-10), Phase 5

## Overview

As a network operator
I want a source PE to advertise a selective per-(S,G) provider tunnel (Type-10
S-PMSI) for a snooped multicast flow, and a Regional Border Router to re-root
that selective tunnel per-region — the selective counterpart of the inclusive
Per-Region I-PMSI (Type-9) aggregation.
Test Topology — z1 is a source PE in region A with an IGMP-snooping bridge; a
snooped (*,239.1.1.1) membership makes it originate a Type-10 S-PMSI. z2 is
the RBR (region A iBGP / region B eBGP); z3 is a PE in region B.
```
┌──────────────────────────────────────────────────────────┐
│                            br0                            │
└─────────┬─────────────────┬─────────────────┬─────────────┘
```

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Setup topology, EVPN sessions, and z1's snooping bridge | |
| A snooped (*,G) makes z1 originate a selective S-PMSI (Type-10) | |
| The RBR re-roots the S-PMSI per-region toward region B | |
| Region B receives the RBR-rooted selective S-PMSI | |
| Teardown topology | |
