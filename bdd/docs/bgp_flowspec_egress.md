# Flowspec egress honours the shared gates

## Overview

As a network operator relaying BGP Flow Specification rules
I want a flow spec's communities to limit where it goes, a neighbor the
rule no longer reaches to lose it, and a neighbor that comes up later to
be sent the rules already held
So flow-spec rules propagate exactly as the other families' routes do.

Flowspec egress skipped the checks every other family applies: a rule
carrying NO_ADVERTISE or NO_EXPORT was sent to every neighbor (RFC
1997); a neighbor the new best no longer reached kept the previous copy;
and the session-up dump had no Flowspec step, so a neighbor that came up
after the rules were learned never got them. The twin is
`bgp_flowspec_egress_v6`, for IPv6 flow specs.

## Test Topology

```
  ┌──────────────────────────────────────────────────────────────────────┐
  │                        br0 192.168.66.0/24                           │
  └─────┬─────────────┬──────────────┬──────────────┬──────────────┬─────┘
   ┌────┴────┐   ┌────┴────┐    ┌────┴────┐    ┌────┴────┐    ┌────┴────┐
   │   z1    │   │   h1    │    │   z2    │    │   z3    │    │   z4    │
   │  (DUT)  │   │ scripted│    │  eBGP   │    │  iBGP   │    │  eBGP   │
   │ AS65001 │   │ AS65001 │    │ AS65002 │    │ AS65001 │    │ AS65004 │
   │  .1     │   │  .2     │    │  .3     │    │  .4     │    │  .5 late│
   └─────────┘   └─────────┘    └─────────┘    └─────────┘    └─────────┘
```

## Notes

h1 (tests/scripts/bgp_flowspec_send.py) announces three destination-prefix
rules: 10.27.3.0/24 with NO_ADVERTISE, 10.27.2.0/24 with NO_EXPORT and 10.27.1.0/24 with no
community, in that order. h1 is an iBGP route-reflector client of z1 and
originates the rules (empty AS_PATH), so they pass RFC 9117 validation.

## Config Files

- z1.yaml: DUT — flowspec-ipv4 to h1 (passive, a reflector client), z2, z3 and z4.
- z2.yaml, z3.yaml, z4.yaml: flowspec-ipv4 to z1.

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Setup; rule 1 reaches every neighbor | |
| A rule carrying NO_EXPORT stays inside the AS | |
| A rule carrying NO_ADVERTISE goes to no neighbor | |
| A neighbor that comes up later is sent the rules already held | |
| A rule its new best no longer lets out is withdrawn from every neighbor | |
| Teardown topology | |
