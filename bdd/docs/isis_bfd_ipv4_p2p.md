# IS-IS BFD over an IPv4 point-to-point link

## Overview

As a network operator running IS-IS over IPv4 links
I want BFD to protect the point-to-point adjacency
So that a forwarding failure tears the adjacency down well within the IS-IS
hold time, and the adjacency stays down (RFC 5882 hold-down) until BFD
recovers — even while IIHs keep arriving.
The single-hop BFD session is built from the two ends' IPv4 interface
addresses (learned via TLV 132). Each scenario is self-contained (own setup
and teardown) so the Echo scenarios configure echo-mode before the session
first comes up (echo is armed at session establishment, not retrofitted).
BFD-down is induced by dropping inbound UDP/3784 in one namespace: the link
stays up and IIHs (L2 ISO PDUs, not IP/UDP) keep flowing, so a fast teardown
is provably BFD's doing — not carrier loss, not the ~30s IS-IS hold timer.

## Test Topology

```
     10.0.1.1/24                             10.0.1.2/24
        (i1)                                   (i1)
    ┌────┴────┐                            ┌────┴────┐
    │   z1    │────────── P2P ─────────────│   z2    │
    └─────────┘                            └─────────┘
   lo 10.255.0.1/32                       lo 10.255.0.2/32
```

## Test Scenarios

| Scenario | Result |
|----------|--------|
| BFD without Echo protects the adjacency and tears it down on BFD failure | |
| BFD with Echo in one direction (z1 transmit, z2 receive) | |
| BFD with Echo in both directions | |
