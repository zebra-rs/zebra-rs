# OSPFv3 TI-LFA fast-reroute over SR-MPLS

## Overview

As a network operator
I want eight zebra-rs instances running OSPFv3 with SR-MPLS (RFC 8666)
and TI-LFA (RFC 9855) to pre-compute a topology-independent loop-free
repair for the source's primary path, so that when the primary link
fails the source still reaches the destination over the SR repair /
post-convergence path.
IPv6 OSPFv3 sibling of `ospfv2_tilfa.feature` / `isis_tilfa.feature`
— the same eight-node RFC 9855 §5 topology and metrics, expressed
through the (new) per-interface `cost` knob, with the v3 SR
machinery (RFC 8362 E-LSAs instead of v2's Opaque LSAs). All links
are point-to-point; every router enables `segment-routing mpls` and
`fast-reroute ti-lfa`. Loopback Prefix-SIDs index 100..800 resolve
against the default SRGB (base 16000). Adjacency-SIDs are NOT
configured: each router allocates one per Full adjacency out of its
SRLB (base 15000) automatically and advertises it as a local (V|L)
Adj-SID — IS-IS-parity dynamic allocation — and the repair encodes
its mid-path hops as those Adj-SID segments.
The metrics are tuned so a simple LFA is impossible: s reaches d via
s-n1 (cost 2); the only other neighbours (n2, n3) are equidistant /
expensive, so protecting the s-n1 first hop requires an SR repair
tunnel through the r-plane rather than a plain loop-free alternate.
OSPFv3 TI-LFA excludes the primary first-hop *vertex* (node
protection) and skips SPF-level ECMP destinations (the remaining
legs already protect the prefix), so repairs exist exactly for r2,
r3 and d — the single-nexthop destinations behind n1. Per RFC 9855
§5.3, the repair for d is <Node-SID(r1), Adj-SID(r1-r2),
Adj-SID(r2-r3)> via first-hop n2: labels [16500, 15xxx, 15yyy] —
the Adj-SID values are whatever r1 / r2 carved from their SRLBs.

## Test Topology

```
                 s (2001:db8::1)
             1 / 1 \      \ 1000
              n1    n2     n3
          1 / |1 \1  \1     \1000
       d ─┘ 1 |   \    \      \
 (2001:db8::8)│    \1000\      \
          1 \ │     r1───────── (r1-n3 1000)
             r3    /  \1000
          1000\   /1   \(r1-r2 1000)
               r2 ──────┘
                 \1000
                  r3 (r3-d 1)
    s-n1 1  s-n2 1  s-n3 1000   n1-r1 1  n2-r1 1  n3-r1 1000
    n1-r2 1 r1-r2 1000 r2-r3 1000  n1-d 1  r3-d 1
```

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Build the TI-LFA topology and confirm adjacencies + routes | |
| SR-MPLS labels and a TI-LFA repair are installed on the source | |
| Source reaches the destination over the primary path | |
| Fast-reroute survives the primary link failure (s-n1) | |
| TI-LFA compute-mode aggressive computes the same repair in parallel | |
| TI-LFA compute-mode sharding bounds parallelism and still protects | |
| Promoted backup actually forwards over the SR-MPLS repair | |
| Disabling fast-reroute clears the repair-list | |
| Deleting segment-routing mpls clears all MPLS ILM entries | |
| Teardown topology | |
