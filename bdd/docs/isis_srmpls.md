# IS-IS SR-MPLS static-route recursive nexthop tracking with TI-LFA

## Overview

As a network operator
I want a static route whose nexthop is a remote loopback (s:
172.168.1.0/24 via 10.0.0.8) to resolve recursively through the
IS-IS SR-MPLS route to that loopback — inheriting its transport
label stack — and to follow the underlay whenever IS-IS changes the
installed path, including a TI-LFA `backup-as-primary` promotion
that swaps the active nexthop of the covering `Protect` route.
End hosts e1 (behind s) and e2 (behind d) carry only static default
routes; an e1 -> e2 ping traverses the SR-MPLS core end-to-end and
dies if any label hop fails to push/swap/pop, so it pins every
static-resolution assertion to real forwarding.
All links are point-to-point veth pairs; every core router is
is-type level-2-only with `segment-routing mpls`. Prefix-SIDs index
100..800 resolve against the RIB's default SRGB (base 16000): s's
node SID is label 16100, n1's 16200, r1's 16500, d's 16800.
`fast-reroute ti-lfa` is deliberately NOT in the startup configs —
it is enabled at runtime mid-feature.
The metrics are tuned so a plain loop-free alternate for the s-n1
link is impossible: n2's shortest path to d (n2-r1-n1-d, cost 3)
ties n2-s-n1-d, so protecting s-n1 needs an SR repair tunnel — P
node r1 (node SID 16500) followed by adjacency SIDs r1->n1 and
n1->d. Adjacency-SID values come from a first-fit SRLB pool (base
15000) keyed on Hello arrival order, so scenarios assert only the
deterministic node-SID labels, never adjacency-SID digits.

## Test Topology

```
   e1 --- s (10.0.0.1)
       1 / 1 \      \ 1000
        n1    n2     n3
    1 / |1 \1  \1     \1000
 d ─┘ 1 |   \    \      \
(10.0.0.8)   \1000\      \
    1 \ |     r1───────── (r1-n3 1000)
       r2    /  \1000
    1000\   /1   \(r1-r2 1000)
         r2 ──────┘
           \1000
            r3 (r3-d 1)   d --- e2
    s-n1 1  s-n2 1  s-n3 1000   n1-r1 1  n2-r1 1  n3-r1 1000
    n1-r2 1 r1-r2 1000 r2-r3 1000  n1-d 1  r3-d 1
```

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Build the SR-MPLS topology with e1/e2 hosts and confirm adjacencies | |
| Static route resolves recursively through the SR-MPLS underlay | |
| Runtime TI-LFA enable computes a repair without moving the static | |
| backup-as-primary promotes the repair to the active route | |
| Static nexthop tracking follows the promoted repair | |
| Reverting backup-as-primary moves the static back | |
| Teardown topology | |
