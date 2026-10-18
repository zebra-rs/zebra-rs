# OSPF elects a DR and a BDR on a broadcast network

## Overview

As a network operator
I want the routers on a broadcast network to agree on a Designated
Router and a Backup Designated Router (RFC 2328 §9.4, RFC 5340
§4.2.2), so every router keeps a full adjacency with both and the BDR
takes over at once when the DR fails.

The election needs every router's Hello to declare the DR and BDR it
has elected. OSPFv2 Hellos used to declare neither: the other routers
then elected the DR as their BDR too, r2 never became BDR, and r1 and
r2 never formed an adjacency. OSPFv3 Hellos always declared them; the
feature checks both versions on the same network.

## Test Topology

```
    r1 (10.0.0.1)    r2 (10.0.0.2)    r3 (10.0.0.3)
         |                |                |
    ------------------- sw (bridge) -------------------
      192.168.10.0/24 and 2001:db8:10::/64, router rN at .N / ::N
```

## Notes

All three run OSPFv2 and OSPFv3 at the default priority, so the
highest Router ID, r3, becomes DR and r2 BDR. When r3 goes, r2 takes
over as DR and r1 becomes BDR.

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Build the broadcast network | |
| The highest Router ID is DR and the next is BDR | |
| The BDR takes over when the DR fails | |
| Teardown topology | |
