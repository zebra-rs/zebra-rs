# BGP MUP PE originates a Direct Segment Discovery (DSD) route over SRv6

## Overview

As a network operator
I want a zebra-rs BGP MUP PE to originate a Direct Segment Discovery
(DSD, type 2, SAFI 85 / draft-ietf-bess-mup-safi) route for an `encapsulation srv6` VRF
when `afi-safi mup segment direct` is configured, so the per-VRF End.DT46
service SID is carved from the locator, installed into the kernel FIB, and
advertised as the segment a receiving PE resolves for matching
Session-Transformed routes (the draft-ietf-bess-mup-safi default).

## Test Topology

```
        2001:db8::1/128            2001:db8::2/128
       ┌──────────┐  IS-IS L2 SRv6  ┌──────────┐
       │    z1    │═════════════════│    z2    │
       │ MUP PE   │   iBGP (mup)    │ receiver │
       │ vrf N6   │                 │          │
       └──────────┘                 └──────────┘
   z1-z2 2001:db8:0:12::1/64   2001:db8:0:12::2/64
```

## Notes

z1 has VRF N6 (`encapsulation srv6`, rd 65501:10) and
`afi-safi mup segment direct`, so it carves an End.DT46 SID from locator
S, installs the seg6local decap into N6's table, and originates a DSD
route (NLRI = rd + router-id 10.0.0.1) carrying that SID. z2 receives it.

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Build topology and establish iBGP with the MUP capability | |
| z1 originates the DSD route and installs the End.DT46 SID | |
| z2 receives the DSD route with the End.DT46 SID | |
| Teardown topology | |
