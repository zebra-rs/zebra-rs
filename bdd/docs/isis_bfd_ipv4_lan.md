# IS-IS BFD over an IPv4 LAN (broadcast) link

## Overview

As a network operator running IS-IS over IPv4 broadcast segments
I want BFD to protect each LAN adjacency
So that a forwarding failure tears the adjacency down well within the IS-IS
hold time, and the adjacency stays down (RFC 5882 hold-down) until BFD
recovers — even while IIHs keep arriving.
Same intent as the point-to-point feature, but the two routers share a Linux
bridge (broadcast network type, DIS election). Per-neighbour single-hop BFD
sessions are built from each end's IPv4 interface address (TLV 132). Each
scenario is self-contained so the Echo scenarios arm echo-mode before the
session first comes up.
BFD-down is induced by dropping inbound UDP/3784 in one namespace: the link
stays up and IIHs (L2 ISO PDUs, not IP/UDP) keep flowing, so a fast teardown
is provably BFD's doing — not carrier loss, not the ~30s IS-IS hold timer.

## Test Topology

```
  ┌────────────────────────────────────────┐
  │                  br0                    │
  └────────────┬───────────────┬───────────┘
               │               │
          10.0.1.1/24     10.0.1.2/24
            (vz1ns)            (vz2ns)
          ┌────┴────┐     ┌────┴────┐
          │   z1    │     │   z2    │
          └─────────┘     └─────────┘
       lo 10.255.0.1      lo 10.255.0.2
              /32                  /32
```

## Test Scenarios

| Scenario | Result |
|----------|--------|
| BFD without Echo protects the LAN adjacency and tears it down on BFD failure | |
| BFD with Echo in one direction (z1 transmit, z2 receive) | |
| BFD with Echo in both directions | |
