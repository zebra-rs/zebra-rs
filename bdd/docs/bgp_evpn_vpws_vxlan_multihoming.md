# BGP EVPN VPWS multihoming over VXLAN — P/B failover binds VTEP and VNI

## Overview

As a network operator
I want a multihomed VPWS pair signalling over VXLAN (RFC 8365 §6) to
fail over exactly like its SRv6 twin — the election and selection
machinery is encapsulation-agnostic — with the remote PE re-binding
BOTH the VTEP and the VNI, because each attached PE advertises its own
VNI in its own Type-1 label field (downstream-assigned: the two ends
of one segment need not agree on a number).

Control-plane only. The topology and carving are bgp_evpn_vpws_multihoming's
(instance 101 carves to ordinal 101 % 2 = 1 = z2, so the LOWER address
deliberately is not the DF), under the default `encapsulation vxlan`
with no SRv6 locator anywhere; z1/z2/z3 advertise VNIs 5111/5222/5333.

```
┌───────────────────────────────────────────────┐
│                      br0                      │
└────┬──────────────────┬──────────────────┬────┘
```

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Setup topology, two PEs on one Ethernet Segment plus a remote PE | |
| Both attached PEs originate VXLAN Type-1s under the segment's ESI | |
| The remote PE binds the primary's VTEP and VNI | |
| Losing the primary fails over to the backup's VTEP and VNI | |
| Teardown topology | |
