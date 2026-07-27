# Dual-homed L3VPN prefix survives one PE's withdraw

## Overview

As a network operator
I want a VRF that imports the same prefix from two PEs (two RDs) to
keep forwarding via the surviving PE when the other withdraws.

## Test Topology

```
  ┌─────────────┐      ┌─────────────┐      ┌─────────────┐
  │     z1      │VPNv4 │     z2      │VPNv4 │     z3      │
  │  AS 65001   │◀───▶│  AS 65001   │◀───▶│  AS 65001   │
  │ vrf-blue    │ iBGP │ vrf-blue    │ iBGP │ vrf-blue    │
  │ RD 65001:1  │      │ RD 65001:2  │      │ RD 65001:3  │
  │ net 10.9.   │      │ (import     │      │ net 10.9.   │
  │  0.0/24     │      │  only)      │      │  0.0/24     │
  └─────────────┘      └─────────────┘      └─────────────┘
   192.168.0.1          192.168.0.2          192.168.0.3
```

## Notes

All three share RT 65001:100. z1 and z3 both export 10.9.0.0/24 under
their own RDs; z2 imports both into vrf-blue. Review finding #4: the
two imports used to alias to one Loc-RIB row in z2's VRF, so either
PE's withdraw removed the row that by then held the OTHER PE's
still-valid route — a CE-side blackhole.

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Setup topology | |
| z2 imports the prefix from both RDs | |
| PE1's withdraw leaves the survivor in the VRF | |
| The survivor's withdraw empties the VRF row | |
| Re-adding the network on PE1 re-imports it | |
| Teardown topology | |
