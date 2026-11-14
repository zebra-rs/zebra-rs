# Static unreachable routes (router static ... nexthop unreachable)

## Overview

`router static ipv4|ipv6 route <prefix> nexthop unreachable` is a
discard route that tells the sender: a packet for the prefix is
dropped here and answered with an ICMP Destination Unreachable
(kernel RTN_UNREACHABLE), so whoever sent it fails at once.
`nexthop blackhole` drops it without a word
(static_blackhole.feature), and the sender waits. A route takes one
of the two keywords.

Topology: h is a plain host behind r, which is zebra-rs and forwards.

## Config Files

- r.yaml: 10.9.9.0/24 and 2001:db8:dead::/48 unreachable, 10.8.8.0/24 and 2001:db8:beef::/48 blackhole, and 10.9.9.0/24 unreachable in VRF blue.
- r_swapped.yaml: the same with the two keywords the other way round.
- r_none.yaml: no static route.

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Setup a router with discard routes of both kinds and a host behind it | |
| The routes are unreachable routes in the RIB and in the kernel | |
| The sender of a packet for an unreachable route is told, and for a blackhole route is not | |
| One keyword takes the other's place in one commit | |
| Both keywords on one route are refused | |
| A restart keeps the unreachable routes | |
| A restart without the routes takes the earlier run's away | |
| A deleted route is withdrawn | |
| Teardown topology | |
