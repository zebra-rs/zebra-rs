# BGP EVPN VPWS E-Line signalling over MPLS (RFC 8365 §5.1.3)

## Overview

As a network operator
I want a `vpws` service under `encapsulation mpls` to advertise its
per-EVI Ethernet A-D route (Type-1) with a per-service MPLS label in
the label field — drawn from the same dynamic block as VRF and EVI
labels — and NO Encapsulation extended community (its absence is what
says MPLS, RFC 8365 §5.1.3), next hop = the router-id the transport
LSP resolves on; and to bind the remote PE's Type-1 as a PE+label
endpoint. Each direction carries the label its EGRESS end assigned.

Control-plane only: no cradle dataplane is attached, so `show bgp evpn
vpws` reaching `up` means the Type-1 exchange, the label-block grant
and the PE+label bind all worked.

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
| Each PE originates a per-EVI Type-1 with a label and no Encapsulation EC | |
| The VPWS service binds the remote PE and label and reaches up | |
| A fabric can run mixed encapsulations, one per direction | |
| Teardown topology | |
