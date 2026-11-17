# BGP update-source by interface name on a per-VRF neighbor

## Overview

As an operator of an L3VPN PE
I want `update-source <interface>` on a per-VRF neighbor to source the
session to the CE from that interface's address, the interface being
one of the neighbor's VRF, so that a CE-facing session follows an
interface as a default-VRF session does.

## Test Topology

```
   ce1 (65001) ── ce1 ─┐
                       ├─ pe1 (65000, vrf-cust)
   ce2 (no router) ─ ce2 ─┘
```

## Notes

PE1's neighbor is CE1, 10.1.0.2 on interface `ce1`, with
`update-source ce2`: the session is to be sourced from the address of
`ce2`, a second interface of the same VRF (10.2.0.1 once the scenario
sets it). The kernel would pick 10.1.0.1, of `ce1`. CE1 is the
observer: it never dials, and has a passive neighbor for each of the
two addresses. So which of CE1's sessions comes up says which address
PE1 sourced the session from.

The session is asserted from CE1, where the neighbor is a default-VRF
one: the `BGP session` step does not see a per-VRF neighbor.

## Test Scenarios

| Scenario | Result |
|----------|--------|
| A per-VRF neighbor is not dialed while the interface has no address | |
| It is dialed from the address of the VRF interface when one comes | |
| Teardown topology | |
