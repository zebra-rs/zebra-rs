# PIM SSM (S,G) forwarding end to end across two routers

## Overview

As a network operator
I want an IGMPv3 source-specific join at the last-hop router to
build an (S,G) shortest-path tree back to the first-hop router and
program the kernel multicast forwarding cache on both, so real
traffic from the source reaches the receiver — the first complete
PIM-SM/SSM control-plane-to-dataplane slice.
h1 sends UDP to the SSM group 232.1.1.1. h2 issues a source-specific
join for (10.1.14.2, 232.1.1.1). r2 (LHR) must translate the IGMPv3
membership into a PIM (S,G) Join toward r1 (RPF via a static route),
r1 (FHR, source directly connected) must accept the Join into its
downstream state, and both must install kernel MFC entries that
forward h1's datagrams to h2.

## Test Topology

```
    h1 (10.1.14.2, sender) --- eth4/eth3 --- r1 --- eth1/eth2 --- r2 --- eth5/eth6 --- h2 (10.1.15.2, receiver)
                                   10.1.14.1     10.1.13.1/.2       10.1.15.1
```

## Test Scenarios

| Scenario | Result |
|----------|--------|
| SSM join builds the (S,G) tree and traffic flows | |
| Teardown topology | |
