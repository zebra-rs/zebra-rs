# BGP MUP Controller originates Session-Transformed routes from PFCP

## Overview

As a network operator
I want the zebra-rs BGP MUP Controller (MUP-C) to learn a mobile session
over PFCP/N4 and originate a Type-1 Session-Transformed route (SAFI 85,
RFC 9833) that a peer zebra-rs receives, so the end-to-end control plane
— PFCP ingest, NI -> VRF correlation, SRv6 SID allocation, ST route
origination, and iBGP advertisement — is validated.

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
VRF `mobile-up` matching Network Instance `access`). `pfcp-inject` plays
the SMF: it sends an Association Setup + Session Establishment for UE
192.0.2.5 (Network Instance `access`), so z1 originates the ST1 route and
advertises it to z2.
NOTE: this feature runs `pfcp-inject` inside z1, so the `pfcp-inject`
binary (the test-only SMF simulator, `tools/pfcp-inject`) must be on the
BDD host PATH — build with `cargo build --release -p pfcp-inject` and
copy `target/release/pfcp-inject` to /usr/bin, the same way the
zebra-rs / vtyctl binaries are staged for BDD.

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Setup topology and establish iBGP session with MUP capability | |
| PFCP session establishment originates an ST1 route received by the peer | |
| Teardown topology | |
