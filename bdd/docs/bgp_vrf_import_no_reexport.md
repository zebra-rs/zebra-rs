# A VRF never re-exports a route it imported

## Overview

As a network operator
I want a PE to stop advertising a VRF prefix into the VPN once it no
longer has a route of its own for it, even while it still imports
another PE's route for the same prefix, so that a prefix nobody
originates any more leaves the VPN.

Before the fix a VRF exported whatever won best-path after one of its
own routes went away. When the only route left was another PE's
import, the VRF re-originated it under its own RD with itself as next
hop, and an import's withdrawal never took that copy back. Two PEs
that import each other's routes then kept the prefix alive after both
stopped originating it: each one's copy re-imported the other's.

## Test Topology

```
  ┌──────────┐ eBGP ┌─────────────┐  VPNv4   ┌─────────────┐
  │    c1    │─────▶│     z1      │◀────────▶│     z2      │
  │ AS 65100 │      │  AS 65001   │   iBGP   │  AS 65001   │
  │ 10.6.0.0 │      │ vrf-blue    │          │ vrf-blue    │
  │  /24     │      │ RD 65001:1  │          │ RD 65001:2  │
  └──────────┘      │ net 10.5.   │          │ net 10.5.   │
   10.9.0.2/30      │  0.0/24     │          │ and 10.6.   │
                    └─────────────┘          └─────────────┘
                     10.9.0.1/30 (c1)         192.168.0.2
                     192.168.0.1
```

## Notes

Both PEs share RT 65001:100. z1 originates 10.5.0.0/24 with a
`network` and 10.6.0.0/24 from its CE c1; z2 originates both with
`network`s. Each PE imports the other's copies, so a PE that drops its
own route for a prefix still holds the other PE's.

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Setup topology | |
| Each PE exports its own routes and imports the other's | |
| A PE whose CE withdraws a prefix stops exporting it | |
| A PE that drops its network stops exporting the prefix | |
| A prefix no PE originates leaves every VRF | |
| Originating again exports again | |
| Teardown topology | |
