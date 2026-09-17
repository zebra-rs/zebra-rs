# BGP-LS carries the IS-IS TE performance metrics

## Overview

As an operator exporting topology to a PCE or controller, I want the
RFC 8570 link performance metrics my IGP advertises to reach the
BGP-LS Loc-RIB as RFC 8571 attributes, so a controller peering over
BGP-LS sees how each link is actually performing and not just its
IGP cost.

Two zebra-rs instances share one P2P link, run IS-IS L2 over it with
static te-metric values, and each runs `router bgp` with the
link-state address family so the IS-IS producer is wired up. Each
router translates its own LSDB into Link-State objects and installs
them in its BGP-LS Loc-RIB, where `show bgp link-state` renders the
translated attributes.

The two ends advertise deliberately different delays, so each value
can be traced to the router that originated it and no assertion can
pass on a default.

The producer walks the whole LSDB, not just the self-originated part,
so each router also translates the LSP its neighbour flooded to it.
That makes this a real round trip for the IS-IS half: ls1 encodes the
RFC 8570 sub-TLVs, ls2 parses them off the wire, and ls2's producer
translates what it parsed into RFC 8571 attributes.

SCOPE: what is *not* covered is the BGP wire. BGP-LS re-advertisement
to peers is not implemented (see `route_bgpls_originate`,
"Re-advertisement to peers is deferred"), so nothing here puts a
BGP-LS Attribute into an UPDATE. The BGP-LS ASLA TLV (1122) encoding
in particular rests on unit tests until an egress path exists to
carry it.

Topology:

## Config Files


## Test Scenarios

| Scenario | Result |
|----------|--------|
| Build the topology | |
| The IS-IS adjacency comes up | |
| Each router originates its own link into the BGP-LS Loc-RIB | |
| The RFC 8570 delay reaches BGP-LS as RFC 8571 attributes | |
| A neighbour's delay survives the IGP wire and the translation | |
| Teardown topology | |
