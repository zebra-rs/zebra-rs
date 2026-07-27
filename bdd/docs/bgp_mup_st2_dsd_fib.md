# BGP MUP interwork node installs the ST2->DSD SRv6 encap

## Overview

An interwork (SRGW) node imports a Type-2 Session-Transformed (ST2) route
and a Direct Segment Discovery (DSD) route (SAFI 85 /
draft-ietf-bess-mup-safi) into a *forwarding* VRF, resolves each ST2 to the
matching DSD by their Direct-segment id (MUP Extended Community), and — the
DSD being remote — installs an SRv6 H.Encaps route for the ST2 endpoint
into the VRF table, resolved through the IS-IS SRv6 underlay toward the
DSD's next-hop. This is the forwarding counterpart of the show-only
interwork resolution.

## Test Topology

```
        2001:db8::1/128            2001:db8::2/128
       ┌──────────┐  IS-IS L2 SRv6  ┌──────────┐
       │    z1    │═════════════════│    z2    │
       │ UPF +    │   iBGP (mup)    │ interwork│
       │ MUP-C    │                 │ (SRGW,   │
       │ (DSD+ST2)│                 │  VRF N6) │
       └──────────┘                 └──────────┘
   z1-z2 2001:db8:0:12::1/64   2001:db8:0:12::2/64
```

## Notes

z1 (VRF N6, rd 65501:10, `segment direct` + `route st2`, export RT
65501:10) originates a DSD (End.DT46 SID from locator S + id 1:2) and, from
a PFCP session on NI `core`, an ST2 (endpoint 10.0.0.1, id 1:2). z2 (VRF
N6, rd 65501:20, `encapsulation srv6`, import RT 65501:10) imports both,
resolves the ST2 to z1's Direct segment, and installs the endpoint encap.

NOTE: needs `pfcp-inject` on the BDD host PATH and root netns (kernel VRF +
seg6 + IS-IS SRv6 underlay).

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Build topology and establish iBGP with the MUP capability | |
| z2 resolves the ST2 to z1's Direct segment and installs the encap | |
| Teardown topology | |
