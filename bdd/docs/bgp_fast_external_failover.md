# BGP fast-external-failover (immediate eBGP reset on link down)

## Overview

As a network operator
I want a directly connected eBGP session to be reset the moment its
interface goes down (IOS-XR `bgp fast-external-fallover`, on by
default), instead of waiting out the 180-second hold timer — and I
want `fast-external-failover false` to restore hold-timer-only
detection.

## Test Topology

```
   ┌─────────┐   10.107.0.0/24   ┌─────────┐
   │   z1    │ i1─────────────i1 │   z2    │
   │ AS65001 │                   │ AS65002 │
   │  .0.1   │                   │  .0.2   │
   └─────────┘                   └─────────┘
```

## Notes

Downing z1's veth end drops carrier on BOTH ends (a veth pair has no
independent carrier), so each router sees its own LinkDown and both
must reset. The default hold time is 180s and the session-state polls
budget 30s, so every "eventually not Established" assertion passing
is itself proof the reset did not come from the hold timer.

## Config Files

- z1.yaml / z2.yaml: direct eBGP over the veth, one originated

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Setup direct eBGP topology and establish the session | |
| Link down resets the session immediately (default enabled) | |
| Link up re-establishes the session without waiting out connect-retry | |
| Disabling fast-external-failover does not bounce the session | |
| With the knob disabled, link down leaves the session to the hold timer | |
| Teardown topology | |
