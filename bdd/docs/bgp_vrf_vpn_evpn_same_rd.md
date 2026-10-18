# A VRF keeps a prefix imported as both VPNv4 and EVPN Type-5 under one RD

## Overview

As a network operator
I want a VRF that imports the same prefix from one PE both as a VPNv4
route and as an EVPN Type-5 route, under the same route distinguisher,
to keep the prefix while either copy is still advertised.

zebra-rs exports a VRF's routes as VPNv4 and, with `evpn
advertise-ipv4`, also as Type-5, both under the VRF's own RD, so a PE
that negotiates both families receives two copies of each route. The
importing VRF used to key an imported row by its origin RD alone: the
two copies were one row, the copy imported last overwrote the other,
and withdrawing either copy removed the prefix from the VRF while the
other was still advertised. Each copy is now its own candidate.

## Test Topology

```
  ┌─────────────┐  VPNv4 + EVPN  ┌─────────────┐
  │     z1      │     iBGP       │     z2      │
  │  AS 65001   │───────────────▶│  AS 65001   │
  │ vrf-blue    │                │ vrf-blue    │
  │ RD 65001:100│                │ RD 65001:200│
  │ net 10.1.   │                │ (import     │
  │  0.0/24     │                │  only)      │
  └─────────────┘                └─────────────┘
   192.168.0.1                    192.168.0.2
```

## Notes

z1 sends 10.1.0.0/24 to z2 in both families under RD 65001:100, with
RT 65001:100, which z2 imports into vrf-blue. An outbound DENY-ALL
policy on one family withdraws only that family's copy (z1-no-evpn.yaml,
z1-no-vpn.yaml); z1-none.yaml denies both.

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Setup topology | |
| z2 receives both copies and imports the prefix | |
| Withdrawing the Type-5 copy leaves the VPNv4 import in the VRF | |
| Both copies are imported again | |
| Withdrawing the VPNv4 copy leaves the Type-5 import in the VRF | |
| Withdrawing both copies empties the VRF | |
| Teardown topology | |
