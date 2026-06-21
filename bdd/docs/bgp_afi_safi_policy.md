# BGP per-AFI neighbor policy under afi-safi (peer-wide fallback)

## Overview

As a network operator I want to bind a route-policy per address family
under `neighbor X afi-safi <name> policy {in,out}`. The per-neighbor
peer-wide `neighbor X policy {in,out}` form has been retired; the only
way to bind a peer-wide route-policy is now through a `neighbor-group`,
which a neighbor inherits as a fallback across families. A per-AFI
binding MUST take priority over the inherited peer-wide one for routes
of that family.
This is observed inbound on z2: z1 originates two /32s; z2's inbound
policy decides which survive in z2's BGP table. Policy edits are picked
up live (soft-reconfiguration inbound), no session reset.

## Test Topology

```
  z1 (AS65001) ──eBGP── z2 (AS65002)
  192.168.0.1/24        192.168.0.2/24
```

## Notes

Both on bridge br0.

## Config Files

- z1.yaml: AS65001, peers z2, originates 10.0.0.1/32 + 10.0.0.2/32.
- z2-base.yaml: AS65002, peers z1, soft-reconfiguration inbound, no
- z2-peerwide-deny.yaml: binds a peer-wide `policy in DENY-ALL` (deny
- z2-perafi-permit.yaml: adds `afi-safi ipv4 policy in PERMIT-ALL`

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Setup sessions; with no policy both routes are accepted | |
| Peer-wide policy inherited from a neighbor-group denies every inbound route | |
| A per-AFI ipv4 policy overrides the inherited peer-wide deny — routes return | |
| Teardown topology | |
