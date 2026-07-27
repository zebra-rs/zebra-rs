# Per-VRF BGP neighbor AS-path knobs (allowas-in, as-override, remove-private-as)

## Overview

As an operator of an L3VPN PE
I want the AS-path manipulation knobs under `router bgp vrf <name>
neighbor <addr>` to take effect on the per-VRF CE session
So that allowas-in, as-override, and remove-private-as behave on a CE
neighbor exactly as on a global neighbor — applied on the per-VRF
receive / advertise path, not silently dropped.
One scenario per knob, each on its own CE neighbor:

## Test Topology

```
   ce2 (65001)
        \
   ce1 ── pe1 (65000, vrf-cust) ── ce3 (65003)
  (65001)
```

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Build the AS-path VRF topology | |
| allowas-in accepts a CE route carrying the PE's own AS | |
| as-override rewrites the shared AS so CE2 accepts the route | |
| remove-private-as strips the private AS toward CE3 | |
| Teardown topology | |
