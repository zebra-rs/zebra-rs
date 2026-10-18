# PIMv6 and MLD show tables fit IPv6 addresses

## Overview

Every PIM show table had fixed columns sized for IPv4: 17 characters
for an address. The tables are shared with PIMv6, where a link-local
address is 25 characters, so it ran straight into the next column:
`fe80::…:4402fe80::…:4402`. A column now grows to its longest cell
plus two spaces; IPv4 output keeps the old layout.

The link-locals are fixed, 25 characters each, so whole rows can be
matched. The host h joins a 22-character group.

## Test Topology

```
   p1 eth1 ─────────── eth2 p2 eth3 ─────────── eth4 h
      fe80::1111:2222:3333:4401  fe80::1111:2222:3333:4402
                                 fe80::1111:2222:3333:4403 (MLD querier)
```

## Config Files

- p1.yaml: PIMv6 on eth1.
- p2.yaml: PIMv6 on eth2 and eth3, MLD on eth3.

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Build the routers with fixed link-local addresses | |
| show pim ipv6 interface keeps Address and DR apart | |
| show pim ipv6 neighbor keeps Neighbor and DR Prio apart | |
| show pim ipv6 mld interface keeps Querier and Address apart | |
| show pim ipv6 mld groups keeps Group and Mode apart | |
| Teardown topology | |
