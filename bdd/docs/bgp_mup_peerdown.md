# BGP MUP peer-down withdraws the RT-imported per-VRF copy

## Overview

As a network operator
I want a BGP MUP route (SAFI 85 / draft-ietf-bess-mup-safi) learned from a
peer to be withdrawn from EVERY table when that peer goes down — not just
the main-instance MUP Loc-RIB but also every VRF that imported it by
route-target — so a session loss cannot leak a stale route (and its derived
SRv6 FIB entry) into a downlink VRF's RIB forever.

## Test Topology

```
        2001:db8::1/128            2001:db8::2/128
       ┌──────────┐  IS-IS L2 SRv6  ┌──────────┐
       │    z1    │═════════════════│    z2    │
       │ MUP PE   │   iBGP (mup)    │ receiver │
       │ N6 (ISD) │                 │ N3 (imp) │
       └──────────┘                 └──────────┘
   z1-z2 2001:db8:0:12::1/64   2001:db8:0:12::2/64
```

## Notes

z1's VRF N6 (rd 65501:20, `encapsulation srv6`, `afi-safi mup segment
interwork prefix 10.60.0.0/16`) originates an ISD carrying export RT
65501:10 and advertises it to z2. z2's VRF N3 (rd 65501:99) imports RT
65501:10, so it pulls the peer-learned ISD in across the RD boundary and
re-keys it under its own rd (65501:99). When z1 is stopped, z2's peer-down
cleanup must drop the ISD from BOTH z2's main MUP Loc-RIB (`show bgp mup`)
and N3's imported copy (`show bgp vrf N3 mup`). Before the fix the main copy
was dropped but N3's RT-imported copy leaked.

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Build topology and establish iBGP with the MUP capability | |
| z2 receives the ISD and imports it into VRF N3 by route-target | |
| When the peer (z1) goes down z2 withdraws the ISD from BOTH tables | |
| Teardown topology | |
