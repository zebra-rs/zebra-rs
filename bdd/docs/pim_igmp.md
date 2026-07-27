# IGMP membership tracking and querier election

## Overview

As a network operator
I want a zebra-rs router to learn IGMP group membership from
attached hosts and to elect a single querier per LAN, so the
receiver side of the multicast control plane works before PIM
trees are built on top of it.

r1 runs IGMP on two links: toward r2 (router-to-router, exercising
querier election — the lower address 10.1.13.1 must win and r2 must
step down to Non-Querier) and toward host h1, which joins group
239.1.1.1 with a socat receiver (the kernel emits an IGMPv3 report);
r1 must show the group in EXCLUDE mode.

## Test Topology

```
    r2 (10.1.13.2) --- eth2/eth1 --- r1 (10.1.13.1)
                                     r1 (10.1.14.1) --- eth3/eth4 --- h1 (10.1.14.2, receiver)
```

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Querier election and receiver join | |
| Teardown topology | |
