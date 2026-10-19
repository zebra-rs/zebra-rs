# A re-exported VRF route carries this PE's forwarding attributes, not the origin's

## Overview

As a network operator
I want an `inter-as-hybrid` VRF that re-exports an imported route to
advertise it with this PE's own forwarding attributes, so a PE that
receives the re-export forwards to this PE as the VRF's encapsulation
says, and not toward the PE the route was first imported from.

A VRF's export starts from the route's attributes as the VRF holds
them. For an imported route those include the forwarding attributes of
the PE that first advertised it: the SRv6 L3 Service SID in its
Prefix-SID attribute, and the Router's MAC and VXLAN Encapsulation
extended communities of a symmetric-IRB Type-5. An SRv6 VRF replaced
the Prefix-SID with its own; an MPLS or VXLAN VRF passed the origin's
on, and the Type-5 path added this PE's Router's MAC beside the
origin's.

## Test Topology

```
  ┌─────────────────────────────────────────────────────────┐
  │                          br0                            │
  └───────┬────────────────────┬────────────────────┬───────┘
     ┌────┴────┐          ┌────┴────┐          ┌────┴────┐
     │   h1    │  EVPN    │   z1    │  VPNv4   │   z2    │
     │ scripted│─iBGP────▶│  (DUT)  │─iBGP────▶│ zebra-rs│
     │ Type-5  │          │vrf-blue │          │vrf-blue │
     │ .32.2/24│          │ hybrid  │          │ .32.3/24│
     └─────────┘          │ .32.1/24│          └─────────┘
                          └─────────┘
```

## Notes

h1 runs tests/scripts/bgp_evpn_type5_send.py and announces
10.20.0.0/24 as a Type-5 with RT 65000:100, the SRv6 SID
fc00:0:2:e000:: (End.DT46), Router's MAC 02:aa:bb:cc:dd:ee and the
VXLAN Encapsulation extended community. z1's vrf-blue (MPLS,
`inter-as-hybrid`) imports it and re-exports it to z2 as VPNv4 under
RD 65000:1, and z2 imports that into its own vrf-blue.

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Setup topology and establish sessions | |
| z1 receives the Type-5 with the origin's forwarding attributes | |
| z1 re-exports the route without the origin's Router's MAC and encapsulation | |
| z2 imports the re-export as an MPLS route toward z1 | |
| Teardown topology | |
