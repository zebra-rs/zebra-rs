# BGP MUP interwork node resolves ST2 to the Direct segment

## Overview

As a network operator
I want a zebra-rs BGP MUP interwork (SRGW) node — `afi-safi mup segment
interwork` — to resolve each received Type-2 Session-Transformed (ST2)
route to the matching Direct Segment Discovery (DSD) route by their BGP
MUP Extended Community (Direct-segment id), so it knows the End.DT46
segment a session's uplink GTP tunnel forwards into
(draft-mpmz-bess-mup-safi §3.3.12, RFC 9433 End.DT46).

## Test Topology

```
        2001:db8::1/128            2001:db8::2/128
       ┌──────────┐  IS-IS L2 SRv6  ┌──────────┐
       │    z1    │═════════════════│    z2    │
       │ UPF +    │   iBGP (mup)    │ interwork│
       │ MUP-C    │                 │  (SRGW)  │
       └──────────┘                 └──────────┘
   z1-z2 2001:db8:0:12::1/64   2001:db8:0:12::2/64
```

## Notes

z1 is a combined UPF + controller: VRF N6 (`encapsulation srv6`, rd
65501:10) with `afi-safi mup segment direct mup-ext-comm 1:2` plus
`route st2 network-instance core mup-ext-comm 1:2` originates a DSD
(End.DT46 SID + Direct-segment id 1:2) and — when `pfcp-inject` programs
a session on Network Instance `core` — an ST2 (same id 1:2). z2 has
`afi-safi mup segment interwork`,
receives both, and resolves the ST2 to z1's End.DT46 Direct segment.

NOTE: needs `pfcp-inject` on the BDD host PATH (cargo build --release -p
pfcp-inject; copy to /usr/bin) and root netns (kernel VRF + seg6local).

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Build topology and establish iBGP with the MUP capability | |
| z1 originates the DSD and (from PFCP) the ST2, both with id 1:2 | |
| z2 (interwork) resolves the ST2 to z1's End.DT46 Direct segment | |
| Teardown topology | |
