# BGP MUP mixed-AFI Session-Transformed route (IPv6 UE, IPv4 endpoint)

## Overview

As a network operator running 5G backhaul where the UE address family and
the N3 transport differ, I want the zebra-rs BGP MUP Controller to
originate a Type-1 Session-Transformed route (SAFI 85,
draft-ietf-bess-mup-safi) for an IPv6 UE whose GTP endpoint (gNB) is IPv4,
and a peer zebra-rs to receive and show it. This validates two behaviours:

## Test Topology

```
           ┌─────────┐     ┌─────────┐
           │   z1    │ iBGP│   z2    │
           │ MUP-C   │◄───►│ receiver│
           │192.168. │     │192.168. │
           │  0.1/24 │     │  0.2/24 │
           └────┬────┘     └─────────┘
                │ PFCP/N4 (UDP 8805)
           ┌────┴───────┐
           │ pfcp-inject │  (SMF simulator, run in z1)
           └────────────┘
```

## Notes

NOTE: this feature runs `pfcp-inject` inside z1, so the `pfcp-inject`
binary (the test-only SMF simulator, `tools/pfcp-inject`) must be on the
BDD host PATH — build with `cargo build --release -p pfcp-inject` and copy
`target/release/pfcp-inject` to /usr/bin, the same way the zebra-rs /
vtyctl binaries are staged for BDD.

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Setup topology and establish iBGP session with MUP capability | |
| IPv6 UE with IPv4 endpoint originates an ST1 route the peer parses | |
| Teardown topology | |
