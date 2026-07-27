# PIMv6 assert election and LAN Join/Prune behaviors

## Overview

As a network operator
I want duplicate forwarders on a shared IPv6 LAN to elect a single
assert winner, routers sharing an upstream LAN to suppress each other's
periodic Joins, and a Prune overheard on a LAN to be overridden by
routers that still want the traffic — the RFC 7761 multi-access
behaviors that keep exactly one copy of each packet on every LAN.

r1 and r2 both connect the upstream LAN swA (toward r0 and the source)
and the contested LAN swB. They must forward the same (S,G) onto swB by
two independent mechanisms — so that DR gating cannot collapse the test
to a single forwarder:

Both forward onto swB and the duplicate data triggers the assert. The
IPv6 assert tiebreak is the link-local source (non-deterministic on
veths), so the winner is made deterministic by RPF cost instead: r2's
static route to the source has a lower metric than r1's, so r2 wins and
r1 steps down, prunes toward r0, and r2 overrides that Prune — the
assert winner then carries swB for both receivers.

## Test Topology

```
    h1(src) - r0 - [swA 2001:db8:61/64] - r1(::2) - [swB 2001:db8:62/64] - r2(::3, DR) - h2(::10 direct)
                                             |             |
                                          r0 also        r3(::1) - h3   (r3 RPFs to r1)
```

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Assert election, join suppression and prune override on LANs | |
| Teardown topology | |
