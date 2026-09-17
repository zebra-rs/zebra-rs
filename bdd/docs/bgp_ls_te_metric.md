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

A third node, lsc, plays the collector: it runs no IGP at all and
peers with ls1 over BGP-LS alone, which is how a PCE or controller
actually attaches. It sits in a different AS and enforces first-AS, so
the feed has to carry a well-formed AS_PATH with ls1's AS at the
front — an originated object whose AS_PATH was left empty is rejected
outright, and the session shows it. Everything in its RIB arrived over the wire, so
that is where the BGP half of the round trip can be observed — the
RFC 8571 attributes and the RFC 9294 ASLA TLV emitted into an UPDATE,
parsed by the receiver, and rendered from the decode.

ls1 and ls2 also peer with each other, but neither can show a received
object as best: each produces the whole LSDB itself, so its own
Originated copy of every object wins path selection. That is correct,
and it is why the collector is necessary rather than convenient.

SCOPE: only self-originated objects are advertised. Re-advertising a
*received* object is route reflection, which is not implemented — so
lsc learns ls1's view of the topology, including the links ls1 learned
from ls2's LSP, but would learn nothing through ls2.

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
| The BGP-LS session comes up | |
| The collector learns the topology over BGP | |
| The RFC 8571 attributes survive the BGP wire | |
| Teardown topology | |
