# BGP EVPN VPWS E-Line signalling over VXLAN (RFC 8365 §6)

## Overview

As a network operator
I want a `vpws` service under the default `encapsulation vxlan` to
advertise its per-EVI Ethernet A-D route (Type-1) with the service VNI in
the label field, the VXLAN Encapsulation extended community and the VTEP
as next hop — no SRv6 locator anywhere — and to bind the remote PE's
Type-1 as a VTEP+VNI endpoint, so an E-Line signals over a plain VXLAN
fabric. Each direction carries the encapsulation its originator
signalled, which is what lets a fabric migrate one PE at a time.

Control-plane only: no cradle dataplane is attached, so the `interface`
leaf is just carried state and `show bgp evpn vpws` reaching `up` means
the Type-1 exchange and the remote VTEP+VNI bind both worked.

Test Topology — two iBGP (AS 65001) EVPN speakers on a shared transport
bridge br0, one E-Line service between them. z1 pins an explicit
`vni 10100`; z2 leaves the leaf unset, so its VNI defaults to the EVI:
```
┌─────────────────────────────────┐
│               br0               │
└───────┬─────────────────┬───────┘
```

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Setup topology and EVPN iBGP with a VPWS service on each PE | |
| Each PE originates a per-EVI Type-1 carrying the VXLAN encapsulation | |
| The VPWS service binds the remote VTEP and VNI and reaches up | |
| Re-pointing remote-service-id rebinds from the Loc-RIB without a route churn | |
| Changing the vni leaf re-originates and the remote end follows | |
| A fabric can run mixed encapsulations, one per direction | |
| A VNI claimed twice parks the second claimant until it is released | |
| Teardown topology | |
