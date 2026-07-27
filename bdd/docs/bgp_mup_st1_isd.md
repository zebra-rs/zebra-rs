# BGP MUP ST1 resolves to a remote ISD segment and installs SRv6 encap

## Overview

An interwork / UPF node imports a remote Interwork Segment Discovery (ISD,
type 1, SAFI 85 / draft-ietf-bess-mup-safi) route — whose prefix is the gNB
N3 network — and — via its MUP controller — originates a Type-1
Session-Transformed (ST1) route whose GTP endpoint (gNB) address falls
inside that prefix. Because the endpoint is covered by the (remote) ISD,
the node resolves the ST1 to the ISD's End.DT46 segment and installs an
SRv6 H.Encaps route for the ST1's **UE prefix** into the VRF table (the
endpoint is the lookup key; the UE prefix is the forwarded destination),
resolved through the IS-IS SRv6 underlay toward the ISD's next-hop.

## Test Topology

```
        2001:db8::1/128            2001:db8::2/128
       ┌──────────┐  IS-IS L2 SRv6  ┌──────────┐
       │    z1    │═════════════════│    z2    │
       │ access PE│   iBGP (mup)    │ UPF +    │
       │  (ISD)   │                 │ MUP-C    │
       └──────────┘                 └──────────┘
   z1-z2 2001:db8:0:12::1/64   2001:db8:0:12::2/64
```

## Notes

z1 (VRF N6, rd 65501:10, `segment interwork prefix 10.0.0.0/24`, export RT
65501:10) originates the ISD (End.DT46 SID from locator S). z2 (VRF N6, rd
65501:20, `encapsulation srv6`, import RT 65501:10) imports the ISD and,
from a PFCP session on NI `access`, originates an ST1 (UE 10.60.1.5, gNB
endpoint 10.0.0.1 inside 10.0.0.0/24). z2 resolves the ST1's endpoint to
z1's segment and installs the UE-prefix encap.

NOTE: needs `pfcp-inject` on the BDD host PATH and root netns (kernel VRF +
seg6 + IS-IS SRv6 underlay).

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Build topology and establish iBGP with the MUP capability | |
| z2 resolves the ST1 to z1's ISD segment and installs the encap | |
| Teardown topology | |
