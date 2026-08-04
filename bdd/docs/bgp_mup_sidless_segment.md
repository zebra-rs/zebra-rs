# A GTP-only MUP PE originates SID-less Segment Discovery routes

## Overview

As a network operator running a GTP-only UPF (dataplane gtp, no SRv6)
I want `segment direct` / `segment interwork` to still advertise the
DSD / ISD routes — without an SRv6 L3 Service Prefix-SID — so a peer can
correlate Session-Transformed routes to my segments by Direct-segment id
and prefix containment (stage 6 of
docs/design/bgp-mup-gtp-segment-resolution-plan.md). The controller
address serves as the next-hop (there is no locator to derive one from).

## Test Topology

```
        2001:db8::1 (lo)                2001:db8::2 (lo)
       ┌──────────────┐     iBGP (mup)  ┌──────────┐
       │      z1      │═════════════════│    z2    │
       │ GTP-only UPF │  over the link  │ receiver │
       │ vrf N3 + N6  │                 │          │
       └──────────────┘                 └──────────┘
   z1-z2 2001:db8:0:12::1/64       2001:db8:0:12::2/64
```

## Notes

z1 has NO segment-routing locator and neither VRF uses `encapsulation
srv6`; both declare `dataplane gtp`. N6 (`segment direct { mup-ext-comm
1:6 }`, rd 65501:20) originates a SID-less DSD; N3 (`segment interwork {
prefix 10.0.1.0/24 }`, rd 65501:10) a SID-less ISD.

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Build topology and establish iBGP with the MUP capability | |
| z1 originates both segments without a Prefix-SID | |
| z2 receives both SID-less segments | |
| Teardown topology | |
