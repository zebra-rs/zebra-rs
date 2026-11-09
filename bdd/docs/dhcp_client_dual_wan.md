# Two DHCP uplinks: backup by distance, ECMP at equal distance

## Overview

Each DHCP interface's lease gives a default route at that interface's
`dhcp-options default-route-distance` (default 210). The DHCP client
hands the RIB the routes of the lowest distance among the uplinks whose
link is up (docs/design/dhcp-client.md D6):

- different distances: the lower one carries the traffic, and the other
- the same distance: one ECMP route over both, what VyOS gets from FRR

Topology: s1 and s2 are two ISPs, each a dnsmasq that is its lease's
router, each with 198.51.100.1 on its loopback: an address r1 reaches
through whichever uplink its default route uses.

## Config Files

- r1.yaml: `address dhcp` on wan0 and wan1, wan1 at distance 220.

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Setup two servers and a router with two DHCP uplinks | |
| The lower distance carries the traffic | |
| The backup takes over while the primary's link is down | |
| The backup takes over when the primary's lease is released | |
| Equal distances share the traffic | |
| Teardown topology | |
