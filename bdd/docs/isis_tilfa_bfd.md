# IS-IS TI-LFA kernel-side fast-reroute on BFD failure

## Overview

As a network operator
I want a BFD-detected primary failure (the link stays up, so the
kernel cannot see it) to rewire the pre-installed protection
indirection groups onto their TI-LFA repairs in one atomic kernel
operation per failed adjacency, BEFORE SPF reconvergence rewrites
the routes — phase 3 of docs/design/nexthop-protect-kernel-failover.md.
The topology is the isis_tilfa SR-MPLS ring with BFD enabled on the
protected s<->n1 adjacency. BFD-down is induced by dropping inbound
UDP/3784 in namespace s: the veth link stays up and IIHs (ISO L2
PDUs, not IP) keep flowing, so the teardown is provably BFD's doing
— the exact failure class the kernel's autonomous link-down path
cannot cover.
The switchover itself is observable only in the daemon log (the
"rewired N protection group(s) onto repairs" line is emitted ONLY
when at least one group actually moved): its kernel state is
superseded within milliseconds by the post-convergence SPF routes,
which is by design — the switchover is a bridge, not a steady state.

## Test Topology

```
                 s (10.0.0.1)
             1 / 1 \      \ 1000
              n1    n2     n3        s-n1 carries BFD; protecting it
          1 / |1 \1  \1     \1000    requires an SR repair through
       d ─┘ 1 |   \    \      \      the r-plane (no plain LFA).
    (10.0.0.8)│    \1000\      \
          1 \ │     r1───────── (r1-n3 1000)
             r3    /  \1000
          1000\   /1   \(r1-r2 1000)
               r2 ──────┘
                 \1000
                  r3 (r3-d 1)
```

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Build the topology and confirm adjacency, BFD, and repairs | |
| BFD-down with the link up triggers the kernel-side switchover | |
| Teardown topology | |
