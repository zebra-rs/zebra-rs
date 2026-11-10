# RA host on WAN interfaces (interface ipv6 address autoconf)

## Overview

`interface <if> ipv6 address autoconf` runs the RA host in the nd task
(docs/design/dhcp-client.md §7): it sends Router Solicitations, and turns
the Router Advertisements it hears into a default route, on-link prefixes
and SLAAC addresses, all through the RIB. The routes are `A` routes at
distance 210, installed as `proto ra`; the kernel's own RA processing is
turned off on the interface (`accept_ra` 0).

Topology: two upstream routers, each on its own WAN interface of r1.

s1 advertises itself with zebra-rs's own RA sender (router lifetime
1800 s, no prefix). s2 sends exactly the RAs a scenario asks for, so
lifetimes, flags and preferences can be driven step by step. Each router
sends from a pinned link-local, and wan1 has a fixed MAC, so the default
route's gateways and the SLAAC address are known in advance.

## Config Files

- s1.yaml: `send-advertisements` on srv0.
- r1.yaml: `address autoconf` on wan0 and wan1.
- r1-wan1.yaml: `address autoconf` on wan1 only.

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Setup two upstream routers and an RA host | |
| The kernel's own RA processing is off on the host's interfaces | |
| Solicitations nobody answers stop after three | |
| An upstream router's RA gives the default route | |
| A prefix gives the on-link route and a SLAAC address, and a high-preference router wins | |
| Router lifetime 0 takes the router away and the other takes over | |
| ra-options orders the two interfaces by distance | |
| A restarted zebra-rs takes its RA routes back from the kernel | |
| Deleting autoconf withdraws the address and the routes | |
| A restart without autoconf on an interface takes the earlier run's RA routes away | |
| Teardown topology | |
