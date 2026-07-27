# BGP EVPN Ethernet Segment discovery (RFC 7432 Type-4)

## Overview

As a network operator
I want each PE attached to a multihomed Ethernet Segment to advertise a
Type-4 Ethernet Segment route (carrying the auto-derived ES-Import RT and a
DF Election EC) and to discover the other PEs on the same ES, so the
control-plane foundation for DF election and all-active multihoming is in
place. (DF election itself and the data plane are later phases.)

Test Topology — two iBGP (AS 65001) EVPN speakers on a shared transport
bridge br0, both configured with the SAME Ethernet Segment es1 / ESI (the
defining property of an ES — the shared CE looks identical to both PEs):
```
┌─────────────────────────────────┐
│               br0               │
└───────┬─────────────────┬───────┘
```

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Setup topology and EVPN iBGP with a shared Ethernet Segment | |
| Each PE originates a Type-4 ES route the other imports | |
| Each PE originates a per-ES Type-1 A-D route the other imports | |
| ES membership shows both PEs on z1 | |
| DF election carves the segment (default service-carving) | |
| Removing the ES on z2 withdraws its Type-4 from z1 | |
| Teardown topology | |
