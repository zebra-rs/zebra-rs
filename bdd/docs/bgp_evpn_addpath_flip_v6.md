# EVPN AddPath members receive every candidate, and a superseded path-id is withdrawn on a flip (IPv6 Type-5)

## Overview

As a network operator
I want an EVPN route reflector with add-path send toward a leaf to send
the leaf every candidate path of an EVPN key and to withdraw the path-id
of a candidate that leaves the reflector's table, so the leaf never keeps
forwarding toward a departed VTEP.

## Test Topology

```
  ┌─────────────┐          ┌─────────────┐          ┌─────────────┐
  │ z1 (VTEP A) │──iBGP──▶│  z2 (RR)    │◀──iBGP──│ z3 (leaf)   │
  │ RD 65001:100│          │ clients:    │ add-path │ add-path    │
  │ Type-5 2001:db8:1::/64│          │ z1, z4, z3  │  send    │ receive     │
  └─────────────┘          └─────────────┘          └─────────────┘
   192.168.0.1                   ▲ 192.168.0.2       192.168.0.3
  ┌─────────────┐                │
  │ z4 (VTEP B) │──────iBGP──────┘
  │ RD 65001:100│
  │ Type-5 2001:db8:1::/64│
  └─────────────┘
   192.168.0.4
```

## Notes

z1 and z4 both originate an EVPN Type-5 for 2001:db8:1::/64 under the SAME route
distinguisher, so the reflector holds two candidates for one EVPN key;
z1's path wins (lower ORIGINATOR_ID). The reflector negotiates AddPath
send toward z3. z4 is brought up only after z1's path is on the leaf, so
z1's path is the best from the start and z4's path is never the best.

Review finding #7: the reflector's AddPath fan-out iterated the single
selected best path, so z3 never received z4's path; and when z1's
session died the survivor was advertised under its own path-id while
z1's path-id was never withdrawn, so z3 kept selecting and forwarding
to the dead VTEP.

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Setup topology | |
| The reflector reflects VTEP A's path to the AddPath leaf | |
| VTEP B comes up and the AddPath leaf receives its path as a second candidate | |
| VTEP A dies and its path-id is withdrawn from the leaf | |
| Teardown topology | |
