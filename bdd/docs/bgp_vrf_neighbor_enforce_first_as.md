# Per-VRF BGP neighbor enforce-first-as

## Overview

As an operator of an L3VPN PE
I want `router bgp vrf <name> neighbor <addr> enforce-first-as` to drop a
CE UPDATE whose left-most AS is not the CE's own AS
So that the RFC 4271 first-AS check runs on the per-VRF CE receive path,
exactly as on a global eBGP neighbor — not silently skipped.

CE1 advertises two routes over one eBGP session:

## Test Topology

```
   ce1 (65001) ── pe1 (65000, vrf-cust)
```

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Build the enforce-first-as VRF topology | |
| A valid first-AS route is accepted | |
| enforce-first-as drops the foreign-first-AS route | |
| Teardown topology | |
