# IS-IS TI-LFA fast-reroute over SR-MPLS

## Overview

As a network operator
I want eight zebra-rs instances running IS-IS Level-2 with SR-MPLS and
TI-LFA (RFC 9490) to pre-compute a topology-independent loop-free
repair for the source's primary path, so that when the primary link
fails the source still reaches the destination over the SR repair /
post-convergence path.
All links are point-to-point veth pairs; every router is is-type
level-2-only with `segment-routing mpls` and `fast-reroute ti-lfa`.
Prefix-SIDs index 100..800 resolve against the RIB's default SRGB
(base 16000), so node s's SID is label 16100, d's is 16800, etc.
The metrics are tuned so a simple LFA is impossible: s reaches d via
s-n1 (cost 2); the only other neighbours (n2, n3) are equidistant /
expensive, so protecting the s-n1 link requires an SR repair tunnel
through the r-plane rather than a plain loop-free alternate.

## Test Topology

```
                 s (10.0.0.1)
             1 / 1 \      \ 1000
              n1    n2     n3
          1 / |1 \1  \1     \1000
       d ─┘ 1 |   \    \      \
    (10.0.0.8)│    \1000\      \
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
| Build the TI-LFA topology and confirm adjacencies + SR | |
| SR-MPLS labels and a TI-LFA repair are installed on the source | |
| Source reaches the destination over the primary path | |
| Fast-reroute survives the primary link failure (s-n1) | |
| no-php sets the P (no-PHP) flag and makes the penultimate hop swap | |
| no-local-prefix-sid suppresses only the local Prefix-SID in the LFIB | |
| Deleting segment-routing mpls clears all MPLS ILM entries | |
| Teardown topology | |
