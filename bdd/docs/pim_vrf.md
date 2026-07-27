# PIM SSM forwarding inside a VRF

## Overview

As a network operator
I want `router pim vrf <name>` to run a full per-VRF PIM instance —
sockets bound into the VRF, the kernel multicast table selected
with MRT_TABLE, IGMP and Join/Prune state scoped to the VRF — so
multicast in one VRF neither sees nor disturbs the default table.
Same shape as the pim_ssm feature, but every router interface is
enslaved to VRF mvrf and all PIM/IGMP config lives under
`router pim vrf mvrf`. The default PIM instance runs with no
interfaces and must stay empty while the mvrf child converges.

## Test Topology

```
    h1 (10.8.14.10, sender) --- eth4/eth3 --- r1 --- eth1/eth2 --- r2 --- eth5/eth6 --- h2 (10.8.15.10, receiver)
                                    10.8.14.1     10.8.13.1/.2       10.8.15.1
```

## Test Scenarios

| Scenario | Result |
|----------|--------|
| SSM join builds the (S,G) tree in the VRF and traffic flows | |
| Teardown topology | |
