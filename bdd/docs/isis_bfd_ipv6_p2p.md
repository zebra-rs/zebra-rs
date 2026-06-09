# IS-IS BFD over an IPv6-only point-to-point link

## Overview

As a network operator running IS-IS over IPv6-only links
I want BFD to protect the point-to-point adjacency
So that a forwarding failure tears the adjacency down well within the IS-IS
hold time, and the adjacency stays down (RFC 5882 hold-down) until BFD
recovers — even while IIHs keep arriving.
The single-hop BFD session is built from the two ends' IPv6 link-local
addresses (learned via TLV 232). Each scenario is self-contained (own setup
and teardown) so the Echo scenarios configure echo-mode before the session
first comes up (echo is armed at session establishment, not retrofitted).
BFD-down is induced by dropping inbound UDP/3784 in one namespace: the link
stays up and IIHs (L2 ISO PDUs, not IP/UDP) keep flowing, so a fast teardown
is provably BFD's doing — not carrier loss, not the ~30s IS-IS hold timer.

## Test Topology

```
   2001:db8:1::1/64                       2001:db8:1::2/64
        (i1)                                   (i1)
    ┌────┴────┐                            ┌────┴────┐
    │   z1    │────────── P2P ─────────────│   z2    │
    └─────────┘                            └─────────┘
  lo 2001:db8:0:ffff::1/128             lo 2001:db8:0:ffff::2/128
```

## Test Scenarios

| Scenario | Result |
|----------|--------|
| BFD without Echo protects the adjacency and tears it down on BFD failure | |
| BFD with Echo in one direction (z1 transmit, z2 receive) | |
| BFD with Echo in both directions | |
