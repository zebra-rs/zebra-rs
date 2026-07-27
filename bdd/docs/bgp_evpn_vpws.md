# BGP EVPN VPWS E-Line signalling over SRv6 (RFC 8214)

## Overview

As a network operator
I want each PE's `vpws` service to advertise a per-EVI Ethernet A-D route
(Type-1) whose Ethernet Tag is its local service instance id, carrying an
End.DX2 L2-Service Prefix-SID (RFC 9252 §6.3) carved from the BGP SRv6
locator, and to bind the remote PE's Type-1 — matched by Ethernet Tag ==
remote-service-id within the shared EVI — as the E-Line's remote end, so
the point-to-point service signals with zero per-peer state.

Control-plane only: no cradle dataplane is attached, so the `interface`
leaf is just carried state and `show bgp evpn vpws` reaching `up` means
the Type-1 exchange and the remote-SID bind both worked.

Test Topology — two iBGP (AS 65001) EVPN speakers on a shared transport
bridge br0, one E-Line service between them:
```
┌─────────────────────────────────┐
│               br0               │
└───────┬─────────────────┬───────┘
```

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Setup topology and EVPN iBGP with a VPWS service on each PE | |
| Each PE originates a per-EVI Type-1 the other imports | |
| The VPWS service binds the remote End.DX2 SID and reaches up | |
| Re-pointing remote-service-id rebinds from the Loc-RIB without a route churn | |
| Mismatched L2 MTUs block the bind until they agree (RFC 8214 §3.1) | |
| Teardown topology | |
