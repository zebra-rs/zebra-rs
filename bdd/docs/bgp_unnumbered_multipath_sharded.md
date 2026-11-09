# BGP multipath over IPv6-unnumbered interface neighbors with RIB sharding

## Overview

As a network operator running an eBGP Clos fabric on unnumbered links
on a leaf with `rib-sharding` above 1
I want equal-cost RFC 8950 paths installed together as one ECMP route,
and `maximum-paths` changes at runtime to reach them
So that sharding the leaf's RIB does not change what it forwards.

bgp_unnumbered_multipath with z1 at `rib-sharding 2`. There the worker
pool owns IPv4-unicast selection: RFC 8950 routes are ingested by the
pool (#2618), the pool shards hold the multipath policy and re-run
selection when it changes (#2617), and `show bgp` marks the second leg
`=` from main's read replica of the pool (#2620). Every step must give
the FIB and markers z1 has at N=1.

Test Topology (both links P2P veth, link-local only — no v4 or
global-v6 addresses anywhere on them):
```
```

z2 and z3 share AS 65000 and both advertise 10.99.0.0/24, so the two
ENHE paths z1 learns tie on every best-path comparison — the
multipath-eligible case, matching the issue's leaf-and-spines fabric.
The expected FIB entry on z1 is FRR-style v4-over-v6 ECMP:
`nexthop via inet6 fe80::.. dev i1` + `nexthop via inet6 fe80::.. dev i2`.

Config files (two-step bring-up per node, same RA race as
bgp_unnumbered_neighbor — see z1-base.yaml for why):
- z1-base.yaml / z1-full.yaml: DUT; both carry `rib-sharding 2` (BGP
- z2-base.yaml / z2-full.yaml: AS 65000, network 10.99.0.0/24
- z3-base.yaml / z3-full.yaml: same as z2 with its own router-id

## Notes

z2 and z3 share AS 65000 and both advertise 10.99.0.0/24, so the two
ENHE paths z1 learns tie on every best-path comparison — the
multipath-eligible case, matching the issue's leaf-and-spines fabric.
The expected FIB entry on z1 is FRR-style v4-over-v6 ECMP:
`nexthop via inet6 fe80::.. dev i1` + `nexthop via inet6 fe80::.. dev i2`.

Config files (two-step bring-up per node, same RA race as
bgp_unnumbered_neighbor — see z1-base.yaml for why):
- z1-base.yaml / z1-full.yaml: DUT; both carry `rib-sharding 2` (BGP
  reads the shard count once, at spawn), full adds RA on i1+i2, the
  two interface-neighbors, and `afi-safi ipv4 maximum-paths 8`
- z2-base.yaml / z2-full.yaml: AS 65000, network 10.99.0.0/24
- z3-base.yaml / z3-full.yaml: same as z2 with its own router-id

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Setup topology | |
| Two equal-cost ENHE paths install as one v4-over-v6 ECMP route | |
| Losing one unnumbered uplink leaves the other leg installed | |
| The uplink coming back restores the second leg | |
| Lowering maximum-paths at runtime collapses the ENHE set | |
| Raising maximum-paths at runtime rediscovers the second leg | |
| Teardown topology | |
