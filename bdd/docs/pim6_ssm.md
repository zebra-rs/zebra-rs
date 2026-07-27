# PIMv6 SSM (S,G) forwarding end to end across two routers

## Overview

As a network operator
I want an MLDv2 source-specific join at the last-hop router to build
an IPv6 (S,G) shortest-path tree back to the first-hop router and
program the kernel MRT6 forwarding cache on both, so real IPv6 traffic
from the source reaches the receiver — the first complete PIMv6
control-plane-to-dataplane slice (MLD + PIMv6 J/P + the MRT6/MIF/MFC
datapath).

h1 sends UDPv6 to the SSM group ff3e::1. h2 issues a source-specific
join for (2001:db8:14::2, ff3e::1). r2 (LHR) must translate the MLDv2
membership into a PIMv6 (S,G) Join toward r1 — its RPF nexthop is r1's
global on the transit link (a static route), which r1 advertises as a
Hello secondary address so r2's neighbor_covers() matches it; the Join
itself is sourced from r2's link-local. r1 (FHR, source directly
connected) accepts the Join into its downstream state, and both
install kernel MRT6 MFC entries that forward h1's datagrams to h2.

## Test Topology

```
    h1 (2001:db8:14::2, sender) --- eth4/eth3 --- r1 --- eth1/eth2 --- r2 --- eth5/eth6 --- h2 (2001:db8:15::2, receiver)
                                       2001:db8:14::1   2001:db8:13::1/.2       2001:db8:15::1
```

## Test Scenarios

| Scenario | Result |
|----------|--------|
| SSM join builds the IPv6 (S,G) tree and traffic flows | |
| Teardown topology | |
