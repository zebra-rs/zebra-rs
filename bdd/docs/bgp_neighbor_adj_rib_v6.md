# show bgp neighbor <X> advertised-routes / received-routes ipv6

## Overview

As a network operator
I want to inspect a single neighbor's IPv6-unicast Adj-RIB-Out and
Adj-RIB-In, so I can see exactly what was advertised to, and received
from, that peer for the v6 address family.
These are the v6-unicast twins of the existing (bare) v4 forms:
`advertised-routes ipv6` reads the peer's `adj_out.v6`, and
`received-routes ipv6` reads its `adj_in.v6`. The IPv6 Adj-RIB-Out
always lives on the peer (the per-peer egress task is v4-only) and the
IPv6 Adj-RIB-In lives in main's shard (v6 ingest never moves to the
pool), so both reads are correct at any shard count.
Topology: one dual-stack point-to-point link, eBGP over the IPv4
transport with both ipv4 and ipv6 afi-safi negotiated, both sides
redistributing connected. The session is keyed by the IPv4 transport
address; the `ipv6` keyword selects the v6 Adj-RIB on that peer.

## Test Scenarios

| Scenario | Result |
|----------|--------|
| A neighbor's v6 Adj-RIB-Out and Adj-RIB-In are visible per peer | |
| A post-establishment v6 prefix appears, then withdraws, from the Adj-RIBs | |
| Teardown topology | |
