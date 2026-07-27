# L2 and L3 EVPN-over-SRv6 coexist on one PE, sharing a SID pool

## Overview

As an operator building an IRB fabric, where the same PE bridges within
a subnet and routes between them
I want `advertise-all-vni` + `encapsulation srv6` (L2) and a VRF with
`encapsulation srv6` + `evpn advertise-ipv4/ipv6` (L3) to run together
on one box, each carving its own SIDs from the one locator, so that the
bridged and routed halves of a tenant are not mutually exclusive.

Every other EVPN-over-SRv6 feature exercises exactly one of the two —
bgp_evpn_srv6_macip is L2 only, bgp_evpn_srv6_type5 is L3 only. Both
allocators draw from the same per-instance SID pool against the same
locator, so coexistence is precisely where an allocator collision or a
reconcile that evicts the other service's SIDs would hide — and it was
the one shape untested.

Control-plane scope for the L2 half (End.DT2U/DT2M forward only through
the cradle tee, which is out of scope here); the L3 half forwards on the
kernel End.DT46 datapath and is asserted as an installed VRF route.

```
```

## Config Files

- z1.yaml, z2.yaml — both services enabled on each PE, one locator each.

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Setup a PE pair running both EVPN services | |
| One locator yields distinct L2 and L3 service SIDs | |
| The peer receives both the L2 and the L3 routes with their SIDs | |
| Both services install, each on its own data path | |
| Withdrawing the L2 MAC leaves the L3 service untouched | |
| Teardown topology | |
