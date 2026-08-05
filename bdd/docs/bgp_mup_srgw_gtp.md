# A dataplane-gtp SRGW steers via remote SRv6 MUP segments

## Overview

The N9/SRGW composite (stage 6 of
docs/design/bgp-mup-gtp-segment-resolution-plan.md): a `dataplane gtp`
VRF whose segments are REMOTE composes GTP with SRv6 instead of ignoring
them. Downlink: an ST1 whose gNB endpoint is covered by a received ISD
(with a usable End.DT46 SID and resolved transport) steers the UE prefix
via SRv6 H.Encaps toward that interwork segment — the segment owner
performs the GTP conversion. Uplink: an ST2 whose Direct-segment id
resolves to a received DSD gets default v4+v6 H.Encaps routes in the
VRF's table, so GTP-decapped traffic rides SRv6 to the anchor. Local
segments always win (this node converts / holds the table itself).

## Test Topology

```
        2001:db8::1/128            2001:db8::2/128
       ┌──────────┐  IS-IS L2 SRv6  ┌──────────┐
       │    z1    │═════════════════│    z2    │
       │ ISD(ACC) │   iBGP (mup)    │ SRGW     │
       │ DSD(ANC) │                 │ gtp VRF  │
       └──────────┘                 └──────────┘
   z1-z2 2001:db8:0:12::1/64   2001:db8:0:12::2/64
```

## Notes

z1 owns BOTH remote segments: VRF ACC (rd 65501:10, `segment interwork
prefix 10.0.0.0/24`, export RT 65501:10) and VRF ANC (rd 65501:30,
`segment direct { mup-ext-comm 1:2 }`, export RT 65501:30), each with an
End.DT46 SID from locator S. z2's VRF mobile (rd 65501:20, `dataplane
gtp`, NO srv6 encapsulation) imports both and originates — from one PFCP
session on NI `access` — an ST1 (UE 10.60.1.5, gNB 10.0.0.1 inside the
ISD prefix) and an ST2 stamped `mup:1:2`.

NOTE: needs `pfcp-inject` on the BDD host PATH and root netns (kernel
VRF + seg6 + IS-IS SRv6 underlay).

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Build topology and import both remote segments | |
| One session drives both composites — SRv6 downlink steer and uplink default | |
| Teardown topology | |
