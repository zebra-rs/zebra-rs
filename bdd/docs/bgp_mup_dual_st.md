# BGP MUP Controller originates both ST1 and ST2 from one PFCP session

## Overview

As a network operator
I want the zebra-rs BGP MUP Controller (MUP-C) to originate every
Session-Transformed route whose VRF binds a session's Network Instance —
so when a downlink (st1) VRF and an uplink (st2) VRF both bind the same
Network Instance, a single PFCP/N4 session originates BOTH the Type-1 ST
(UE prefix + access tunnel) and the Type-2 ST (core endpoint + GTP TEID),
not just the first matching VRF.

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

z1 runs the controller (PFCP listener on 192.168.0.1:8805, locator LOC1)
with two VRFs binding Network Instance `internet`: `mobile-dl`
(rd 65000:101, `afi-safi mup route st1`) for the downlink Type-1 ST, and
`mobile-ul` (rd 65000:100, `afi-safi mup route st2` carrying Direct
segment id `1:2`) for the uplink Type-2 ST. `pfcp-inject` plays the SMF:
it sends an Association Setup + Session Establishment for UE 192.0.2.5 with
an ACCESS-side F-TEID (gNB endpoint 10.0.0.1 / TEID 0x12345678) and a
CORE-side F-TEID (endpoint 10.9.0.1 / TEID 0x87654321), Network Instance
`internet`. The Type-1 ST carries the access endpoint, the Type-2 ST the
core endpoint (draft §3.3.7 / §3.3.10 — they are distinct), and z1
advertises BOTH to z2.
NOTE: this feature runs `pfcp-inject` inside z1, so the `pfcp-inject`
binary (`tools/pfcp-inject`) must be on the BDD host PATH — build with
`cargo build --release -p pfcp-inject` and copy `target/release/pfcp-inject`
to /usr/bin, the same way the zebra-rs / vtyctl binaries are staged.

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Setup topology and establish iBGP session with MUP capability | |
| One PFCP session originates both an ST1 and an ST2 route received by the peer | |
| Teardown topology | |
