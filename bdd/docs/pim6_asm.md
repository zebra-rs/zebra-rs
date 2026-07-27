# PIMv6 ASM with a static RP — register, shared tree and SPT

## Overview

As a network operator
I want an any-source MLD join at the last-hop router to build a shared
tree to the static RP, a new IPv6 source's first-hop router to register
it with the RP, the RP to join the source tree and stop the registers,
and traffic to flow natively source→RP→receiver — the complete PIMv6-SM
ASM control loop over three routers.

r2 is the RP (2001:db8:12::2, its own interface address, configured
statically on all three routers). h2 issues an any-source join for
ff0e::1 (MLDv2 EXCLUDE{}); r3 (LHR) builds (*,G) toward the RP. h1 then
sends: r1 (FHR/DR for the source subnet) registers with the RP, the RP
joins (S,G) back toward r1 and answers Register-Stop — r1's register
state must settle in RegPrune — and h1's datagrams must arrive at h2
through the kernel MRT6 MFCs of all three routers.

## Test Topology

```
    h1 (2001:db8:1::9, sender) -- eth0/eth1 -- r1 -- eth2/eth3 -- r2(RP) -- eth4/eth5 -- r3 -- eth6/eth7 -- h2 (2001:db8:24::9, receiver)
                                    2001:db8:1::1   2001:db8:12::1/.2       2001:db8:23::1/.2         2001:db8:24::1
```

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Register, shared tree and SPT converge and traffic flows | |
| Teardown topology | |
