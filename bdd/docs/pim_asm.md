# PIM ASM with a static RP — register, shared tree and SPT

## Overview

As a network operator
I want an any-source IGMP join at the last-hop router to build a
shared tree to the static RP, a new source's first-hop router to
register it with the RP, the RP to join the source tree and stop
the registers, and traffic to flow natively source→RP→receiver —
the complete PIM-SM ASM control loop over three routers.
r2 is the RP (10.1.22.2, its own interface address, configured
statically on all three routers). h2 issues an any-source join for
239.2.2.2 (IGMPv3 EXCLUDE{}); r3 (LHR) builds (*,G) toward the RP.
h1 then sends: r1 (FHR/DR for the source subnet) registers with the
RP, the RP joins (S,G) back toward r1 and answers Register-Stop —
r1's register state must settle in suppression (RegPrune) — and
h1's datagrams must arrive at h2 through the kernel MFCs of all
three routers.

## Test Topology

```
    h1 (10.1.21.2, sender) -- eth0/eth1 -- r1 -- eth2/eth3 -- r2(RP) -- eth4/eth5 -- r3 -- eth6/eth7 -- h2 (10.1.24.2, receiver)
                                 10.1.21.1    10.1.22.1/.2       10.1.23.1/.2          10.1.24.1
```

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Register, shared tree and SPT converge and traffic flows | |
| Teardown topology | |
