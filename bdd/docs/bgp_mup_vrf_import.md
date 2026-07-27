# BGP MUP cross-VRF import by route-target (RD-independent)

## Overview

As a network operator
I want a locally-originated BGP MUP route (SAFI 85 / draft-ietf-bess-mup-safi) to be
imported into every VRF whose `mup route-target import` overlaps the
route's RTs — not just the VRF that owns the route's RD — so per-VRF MUP
matches the VPNv4/v6 import model and a downlink VRF can pull in the
upstream segment another VRF originated.

## Test Topology

```
        2001:db8::1/128            2001:db8::2/128
       ┌──────────┐  IS-IS L2 SRv6  ┌──────────┐
       │    z1    │═════════════════│    z2    │
       │ MUP PE   │   iBGP (mup)    │ receiver │
       │ N6 + N3  │                 │          │
       └──────────┘                 └──────────┘
   z1-z2 2001:db8:0:12::1/64   2001:db8:0:12::2/64
```

## Notes

On z1, VRF N6 (rd 65501:20, `encapsulation srv6`, `afi-safi mup segment
interwork prefix 10.60.0.0/16`) originates an ISD route carrying its export
RT 65501:10. VRF N3 (rd 65501:10) imports RT 65501:10, so it pulls in N6's
ISD even though the ISD's RD (65501:20) does not equal N3's own rd — the
proof that per-VRF MUP import is route-target matched, not RD matched.

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Build topology and establish iBGP with the MUP capability | |
| z1 originates the ISD in N6 and installs the End.DT46 SID | |
| N6 self-imports its own ISD (rd 65501:20 imports rt 65501:10) | |
| N3 imports N6's ISD across the RD boundary by route-target | |
| z2 receives the ISD route with the End.DT46 SID | |
| Teardown topology | |
