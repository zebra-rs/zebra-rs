# BGP MUP End.DT46 datapath forwards real traffic (ST2 -> DSD)

## Overview

Two combined MUP UPF + interwork nodes (z1, z2) each terminate a PFCP
session (NI `core`) and originate a Type-2 Session-Transformed (ST2) route
whose endpoint is a host behind it (ceA behind z1, ceB behind z2), plus a
Direct Segment Discovery (DSD) route carrying the per-VRF End.DT46 SID
(draft-ietf-bess-mup-safi, SAFI 85). Each imports the other's DSD + ST2 and
resolves them by Direct-segment id (MUP Extended Community), installing an
SRv6 H.Encaps route for the remote ST2 endpoint toward the remote End.DT46
SID, resolved through the IS-IS SRv6 underlay. So a bidirectional ceA<->ceB
ping traverses the MUP End.DT46 datapath in BOTH directions using only
MUP-installed routes — the forwarding counterpart of bgp_mup_st2_dsd_fib
(which asserts the install; this drives real packets through it).

zebra-rs uses End.DT46 as the mainline-kernel stand-in for the draft's
GTP-U edge behaviours (GTP4.E / H.M.GTP4.D), which need a VPP/eBPF forwarder
(see docs/design/bgp-mup-dataplane-plan.md, Plan A). Because a VRF binds a
single MUP direction, one bidirectional subscriber path is realized by two
collocated nodes (each an ST2 anchor for its own host), not one.

## Test Topology

```
        2001:db8::1/128            2001:db8::2/128
   ceA ─┤    z1    │══ IS-IS L2 ══│    z2    ├─ ceB
 10.10.1.2  UPF+MUP-C  SRv6+iBGP   UPF+MUP-C  10.20.2.2
   /24  │ VRF N6   │   (mup)      │ VRF N6   │  /24
        └──────────┘              └──────────┘
   z1-z2 2001:db8:0:12::1/64  2001:db8:0:12::2/64
```

## Notes

NOTE: needs `pfcp-inject` on the BDD host PATH and root netns (kernel VRF +
seg6 + IS-IS SRv6 underlay).

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Build topology and establish iBGP with the MUP capability | |
| Each node resolves the peer ST2 to its DSD and installs the encap | |
| ceA <-> ceB traffic forwards over the MUP End.DT46 datapath | |
| Teardown topology | |
