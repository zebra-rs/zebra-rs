# ECMP leg eviction on BFD failure

## Overview

As a network operator
I want a BFD-detected failure of one ECMP leg (the link stays up,
so the kernel cannot see it) to evict that leg from the kernel
nexthop groups in one atomic replace per group, BEFORE SPF
reconvergence rewrites the routes — phase 5 of
docs/design/nexthop-protect-kernel-failover.md.
TI-LFA deliberately computes no repair for SPF-level ECMP
destinations: the surviving legs ARE the protection. This feature
proves that holds for the link-up failure class too — without the
eviction, the kernel would keep hashing flows onto the dead leg
until SPF finishes.
Like the switchover, the eviction is observable only in the daemon
log ("evicted failed leg from N ECMP group(s)" is emitted ONLY when
at least one group shrank): SPF supersedes its kernel state within
milliseconds, by design.

## Test Topology

```
        s (10.0.0.1)
       / \
     s-a  s-b          BFD runs on the s<->a leg only.
     /      \
    a        b
     \      /
     a-d  b-d
       \ /
        d (10.0.0.4)
```

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Build the diamond and confirm ECMP, BFD, and reachability | |
| BFD-down on one leg evicts it from the kernel ECMP group | |
| Teardown topology | |
