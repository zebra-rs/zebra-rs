# BGP multipath over IPv6-unnumbered interface neighbors

## Overview

As a network operator running an eBGP Clos fabric on unnumbered links
I want equal-cost RFC 8950 paths (v6 link-local next-hop, one per
uplink) installed together as one ECMP route
So that a leaf with several unnumbered uplinks load-shares instead of
pinning all traffic to a single spine (issue #2318 — the multipath
dedup keyed on the next-hop attribute, which an ENHE path does not
have, so every unnumbered path collapsed into a "duplicate" of the
winner and `maximum-paths` silently did nothing).

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
- z1-base.yaml / z1-full.yaml: DUT; full adds RA on i1+i2, the two
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
- z1-base.yaml / z1-full.yaml: DUT; full adds RA on i1+i2, the two
  interface-neighbors, and `afi-safi ipv4 maximum-paths 8`
- z2-base.yaml / z2-full.yaml: AS 65000, network 10.99.0.0/24
- z3-base.yaml / z3-full.yaml: same as z2 with its own router-id

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Setup topology | |
| Two equal-cost ENHE paths install as one v4-over-v6 ECMP route | |
| Losing one unnumbered uplink leaves the other leg installed | |
| The uplink coming back restores the second leg | |
| Teardown topology | |
