# BGP MUP Controller originates a Type-2 ST route from a PFCP session

## Overview

As a network operator
I want the zebra-rs BGP MUP Controller (MUP-C) to learn a mobile session
over PFCP/N4 and originate a Type-2 Session-Transformed route (ST2, SAFI
85, draft-mpmz-bess-mup-safi §3.1.4) for the uplink (N3) — the
core endpoint + GTP TEID with the BGP MUP Extended Community of the Direct
segment — so a peer zebra-rs receives it and the End.DT46 uplink/downlink
forwarding model can be programmed from the Direct segment.

## Test Topology

```
  ┌─────────────────────────────────────────┐
  │                   br0                    │
  └─────────────┬───────────────┬───────────┘
                │               │
           ┌────┴────┐     ┌────┴────┐
           │   z1    │     │   z2    │
           │ MUP-C   │ iBGP│ receiver│
           │192.168. │◄───►│192.168. │
           │  0.1/24 │     │  0.2/24 │
           └────┬────┘     └─────────┘
                │ PFCP/N4 (UDP 8805)
           ┌────┴──────┐
           │ pfcp-inject│  (SMF simulator, run in z1)
           └───────────┘
```

## Notes

z1 runs the controller (PFCP listener on 192.168.0.1:8805, locator LOC1,
VRF `mobile-up` with `afi-safi mup segment direct` plus `route st2
network-instance core` binding Network Instance `core` to its Type-2 ST /
Direct segment, and carrying the Direct segment id `1:2` on both the
segment and the st2 route). `pfcp-inject` plays the SMF: it
sends an Association Setup + Session Establishment for endpoint 10.0.0.1 /
TEID 0x12345678 (Network Instance `core`), so z1 originates the ST2 route
and advertises it to z2.
NOTE: this feature runs `pfcp-inject` inside z1, so the `pfcp-inject`
binary (`tools/pfcp-inject`) must be on the BDD host PATH — build with
`cargo build --release -p pfcp-inject` and copy `target/release/pfcp-inject`
to /usr/bin, the same way the zebra-rs / vtyctl binaries are staged.

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Setup topology and establish iBGP session with MUP capability | |
| PFCP session establishment originates an ST2 route received by the peer | |
| Teardown topology | |
