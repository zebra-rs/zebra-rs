# BGP unnumbered neighbor on a router with RIB sharding

## Overview

As a network operator running BGP over IPv6-only point-to-point links
on a router with `rib-sharding` above 1
I want the IPv4 routes an unnumbered neighbor sends (RFC 8950, IPv6
link-local next-hop) to leave the kernel FIB when the neighbor
withdraws them or the session goes down
So that the router does not keep forwarding into a neighbor that no
longer offers the route.

At N>1 the worker pool owns IPv4-unicast selection, and withdraws and
session clean-up go to the pool. RFC 8950 routes used to be ingested on
main instead, where the pool's withdraw and peer-down never reached
them: z1 kept both of z2's routes in its FIB after a withdraw and after
the session went down. Only z1 is sharded; z2 is the plain neighbor.

Test Topology (P2P veth, link-local only — no v4/global-v6 addrs on
i1; the LAN prefixes live on dummy interfaces):
```
```

## Config Files

- z1-base.yaml / z2-base.yaml: a bare `router bgp` block, so ND learns
  i1 before RA is enabled (see bgp_unnumbered_neighbor). z1's already
  carries `rib-sharding 2`: BGP reads the shard count once, at spawn.
- z1-full.yaml / z2-full.yaml: RA on i1 and `interface-neighbor i1`.
  z2 advertises 10.10.2.0/24 and 10.0.0.2/32 with a zero MRAI.
- z2-withdraw.yaml: z2-full.yaml without 10.10.2.0/24.

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Setup topology | |
| The sharded router installs the unnumbered neighbor's IPv4 routes | |
| A withdrawn route leaves the sharded router's FIB | |
| Losing the session removes the routes from the sharded router's FIB | |
| Teardown topology | |
