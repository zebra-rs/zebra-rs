# BGP unnumbered neighbor visible in summaries before any session

## Overview

As a network operator bringing up BGP over IPv6-only point-to-point
links, I want a configured `interface-neighbor` to appear in
`show bgp summary` (as Idle) even when the remote node has never been
reachable, so that mis-cabled or not-yet-deployed neighbors are
diagnosable from the summary instead of silently absent.
Interface-keyed peers are normally materialized only when the
remote's Router Advertisement surfaces its link-local. This feature
pins the dormant-materialization path: config + link knowledge alone
must create the operator-visible peer (FRR behaves the same way).
Test Topology (point-to-point veth; z2 exists only to hold the other
veth end — it never runs zebra-rs, so z1 never sees an RA):
```
```

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Setup topology | |
| A never-connected interface-neighbor is listed as a dormant Idle peer | |
| Teardown topology | |
