# ECMP leg eviction and restore on BFD failure (OSPFv2)

## Overview

As a network operator
I want a BFD-detected failure of one ECMP leg to evict that leg from
the kernel nexthop groups, and the leg to come BACK when BFD
recovers — the OSPFv2 sibling of ecmp_bfd_evict.feature.

The eviction half is shared with IS-IS: `protect_switch` shrinks each
affected kernel group in one atomic replace. The restore half is not.
OSPF's BFD-down handler unsubscribes the session and ignores every
transition that is not to Down, so there is no BFD "up" event to react
to; recovery instead arrives as the adjacency re-forming from hellos
and re-arming BFD in `bfd_reconcile_nbr`.

Without a restore there, the group stays shrunk whenever reconvergence
does not rewrite the affected prefixes — which is exactly what happens
when the adjacency returns before SPF ran. The failure is silent and
asymmetric, and this feature is written to catch precisely that: the
RIB keeps reporting both legs while the kernel forwards over one, so
asserting on `show ip route` alone would pass. The kernel route is the
assertion that matters.

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
| BFD-down evicts the leg, and BFD-up brings it back | |
| Teardown topology | |
