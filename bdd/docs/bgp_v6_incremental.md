# IPv6 unicast routes appearing after session establishment are advertised

## Overview

As a network operator
I want an IPv6 route that shows up while a BGP session is already
Established to be advertised to that peer, so convergence does not
depend on session resets.
Regression guard: the incremental v6 advertise path
(`route_advertise_to_peers_v6`) emits reach only through the
per-update-group `cache_ipv6`, but `(Ip6, Unicast)` was never in
`TRACKED_AFI_SAFIS`, so `update_group::attach` never enrolled any
peer and the group lookup always missed — incremental v6 reach was
silently dropped. Only the initial `route_sync_ipv6` dump at
establishment delivered v6 routes, which is why every pre-existing
feature (config applied before the session comes up) kept passing.
Topology: one dual-stack point-to-point link, eBGP over the IPv4
addresses with both ipv4 and ipv6 afi-safi negotiated, both sides
redistributing connected. adv-interval is pinned to 1s. The route
under test is injected via a dummy interface created only AFTER the
session is verified Established, so it can only reach the peer
through the incremental path.

## Test Scenarios

| Scenario | Result |
|----------|--------|
| A connected v6 prefix added after Established reaches the peer | |
| Withdrawing the prefix after Established removes it from the peer | |
| Teardown topology | |
