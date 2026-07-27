# PIMv6 SSM forwarding inside a VRF

## Overview

As a network operator
I want `router pim vrf <name> ipv6` to run a full per-VRF PIMv6
instance — sockets bound into the VRF, the kernel MRT6 table selected
with MRT6_TABLE, MLD and Join/Prune state scoped to the VRF — so IPv6
multicast in one VRF neither sees nor disturbs the default table.

Same shape as the pim6_ssm feature, but every router interface is
enslaved to VRF mvrf and all PIMv6/MLD config lives under
`router pim vrf mvrf ipv6`. The parent's per-VRF Pim<Ipv4> child spawns
a per-VRF Pim<Ipv6> grandchild; the default IPv6 instance is never
configured and must stay absent.

## Test Topology

```
    h1 (2001:db8:14::10, sender) --- eth4/eth3 --- r1 --- eth1/eth2 --- r2 --- eth5/eth6 --- h2 (2001:db8:15::10, receiver)
                                       2001:db8:14::1   2001:db8:13::1/.2       2001:db8:15::1
```

## Test Scenarios

| Scenario | Result |
|----------|--------|
| SSM join builds the (S,G) tree in the VRF and traffic flows | |
| Teardown topology | |
