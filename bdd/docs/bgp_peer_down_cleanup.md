# BGP session loss withdraws every AFI/SAFI the peer contributed

## Overview

As a network operator
I want a BGP session that leaves Established to take all of that
neighbour's routes with it — across every negotiated AFI/SAFI — so
that traffic never follows a route whose only source is a dead peer.
Regression guard: `route_clean` (the leaving-Established hook) used
to cover IPv4 unicast, VPNv4, EVPN and labeled-unicast but skipped
IPv6 unicast entirely — a session drop left the peer's IPv6 routes
best-path-selected forever, while the same peer's IPv4 routes were
correctly withdrawn. The fix also swept the same gap for VPNv6,
Flowspec, BGP-LS and SR Policy; this feature pins the dual-stack
unicast behaviour end to end.
Topology: one dual-stack point-to-point link, eBGP over the IPv4
addresses with both ipv4 and ipv6 afi-safi negotiated, both sides
redistributing connected (loopbacks 10.0.0.X/32 + 2001:db8::X/128).

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Establish the dual-stack session and learn both AFIs | |
| Killing the peer withdraws IPv4 AND IPv6 routes | |
| The session re-establishes and both AFIs are re-learned | |
| Teardown topology | |
