# PIMv6 Bootstrap Router election and RP-set distribution

## Overview

As a network operator
I want a candidate BSR to win the election, collect candidate-RP
advertisements, and flood the RP-set in Bootstrap messages so every
PIMv6 router learns the group-to-RP mapping without static config —
then run the ASM control loop on the BSR-learned RP.

r2 is candidate-BSR and candidate-RP (2001:db8:22::2). r1 and r3 must
learn both the elected BSR and the RP purely from flooded BSMs. The
Bootstrap messages are link-local-sourced multicast (like Hellos); the
BSR / RP addresses they carry are the configured globals, so the
election and RP mapping are deterministic.

## Test Topology

```
    h1 (2001:db8:21::10, sender) -- eth0/eth1 -- r1 -- eth2/eth3 -- r2(C-BSR,C-RP) -- eth4/eth5 -- r3 -- eth6/eth7 -- h2 (2001:db8:24::10, receiver)
                                       2001:db8:21::1   2001:db8:22::1/.2         2001:db8:23::1/.2         2001:db8:24::1
```

## Test Scenarios

| Scenario | Result |
|----------|--------|
| BSR election, RP-set distribution and ASM traffic | |
| Teardown topology | |
