# PIM Bootstrap Router elects itself and distributes the RP-set

## Overview

As a network operator
I want a candidate BSR to win the election, collect candidate-RP
advertisements and flood the group-to-RP mapping in Bootstrap
Messages, so every router in the domain learns the RP without any
static configuration — and the full ASM control loop (shared tree,
register, SPT) runs on the learned mapping.
Same chain as the pim_asm feature, but NO router has a static RP:
r2 is candidate-BSR and candidate-RP (10.9.22.2). r1 and r3 must
learn both the elected BSR and the RP purely from flooded BSMs,
after which an any-source join at h2 and a sender at h1 must
converge exactly as the static-RP scenario did.

## Test Topology

```
    h1 (10.9.21.10, sender) -- eth0/eth1 -- r1 -- eth2/eth3 -- r2(C-BSR,C-RP) -- eth4/eth5 -- r3 -- eth6/eth7 -- h2 (10.9.24.10, receiver)
                                  10.9.21.1    10.9.22.1/.2          10.9.23.1/.2               10.9.24.1
```

## Test Scenarios

| Scenario | Result |
|----------|--------|
| BSR election, RP-set distribution and ASM traffic | |
| Teardown topology | |
