# PIM assert election and LAN Join/Prune behaviors

## Overview

As a network operator
I want duplicate forwarders on a shared LAN to elect a single
assert winner, a router's overheard Join on a shared upstream LAN
to suppress the other joined router's periodic refresh (leaving
one refresher per LAN), and a Prune overheard on a LAN to be
overridden by routers that still want the traffic — the RFC 7761
multi-access behaviors that keep exactly one copy of each packet
on every LAN.

r1 and r2 both connect the upstream LAN swA (toward r0 and the
source) and the contested LAN swB. They must forward the same
(S,G) onto swB by two independent mechanisms — so that DR gating
(only the DR turns local membership into forwarding state) cannot
collapse the test to a single forwarder:

Both forward onto swB, the duplicate data triggers the assert, and
the higher address (r2, 10.6.2.3) wins. r1 steps down; with its
only outgoing interface assert-lost its JoinDesired collapses and
it prunes toward r0. r2 overhears that Prune and overrides it,
keeping r0 forwarding, and the assert winner then carries the LAN
for both receivers.

## Test Topology

```
    h1(src) - r0 - [swA 10.6.1/24] - r1(.2) - [swB 10.6.2/24] - r2(.3, DR) - h2(.10 direct)
                                        |             |
                                     r0 also        r3(.1) - h3   (r3 RPFs to r1)
```

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Assert election, join suppression and prune override on LANs | |
| Teardown topology | |
