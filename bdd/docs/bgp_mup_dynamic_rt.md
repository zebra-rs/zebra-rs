# BGP MUP export route-target applies dynamically to an originated ST route

## Overview

As a network operator
I want a `set vrf <name> mup route-target export <rt>` change to take
effect on an already-originated controller Session-Transformed route,
re-stamping it with the new route-target and re-advertising it — without
re-establishing the PFCP session. The export RTs are read from the VRF
table at session-establish time, so a route originated before the RT is
configured (or before a later export-RT commit) must be re-tagged in
place. This regressed: the export-RT change refreshed only the DSD/ISD
segment routes, never the controller's ST1/ST2 routes, so the new RT
never reached the route or the peer.

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

z1 runs the controller (PFCP listener on 192.168.0.1:8805, VRF
`mobile-up` binding Network Instance `core` to a Type-2 ST route with the
Direct segment id `1:2`). The top-level `vrf mobile-up` starts with NO
`mup route-target export`. z2 imports MUP route-target 100:10. The
feature injects a session (z1 originates the ST2 with no RT), then applies
`set vrf mobile-up mup route-target export 100:10` at runtime and checks
the ST2 is re-stamped on z1 and the re-advertised route reaches z2's
per-VRF view (which only imports 100:10).

NOTE: this feature runs `pfcp-inject` inside z1, so the `pfcp-inject`
binary (`tools/pfcp-inject`) must be on the BDD host PATH — build with
`cargo build --release -p pfcp-inject` and copy `target/release/pfcp-inject`
to /usr/bin, the same way the zebra-rs / vtyctl binaries are staged.

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Setup topology and establish iBGP session with MUP capability | |
| Originate an ST2 with no export RT, then apply the export RT dynamically | |
| Teardown topology | |
