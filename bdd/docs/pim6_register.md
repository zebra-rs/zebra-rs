# PIMv6 FHR Register to a static RP over unicast IPv6

## Overview

As a network operator
I want a first-hop router to encapsulate a new IPv6 source's traffic
in a PIM Register and unicast it to the statically configured RP, and
the RP to answer Register-Stop so the FHR settles in suppression — the
PIMv6 unicast Register control loop (transport slice of ASM), before
the full shared-tree datapath.

Unlike link-local PIM control (Hello / J/P / Assert to ff02::d), the
Register and Register-Stop are unicast between the FHR and the RP: the
FHR sources them from a routable (non-link-local) address so the RP can
reply, and the RP accepts a non-link-local source on a unicast
destination. There is no receiver, so the RP has no shared tree and
answers Register-Stop immediately; the FHR's register state settles in
RegPrune.

## Test Topology

```
    h1 (2001:db8:1::9, source) --- eth0/eth1 --- r1 (FHR) --- eth2/eth3 --- r2 (RP, 2001:db8:12::2)
                                       2001:db8:1::1        2001:db8:12::1/.2
```

## Test Scenarios

| Scenario | Result |
|----------|--------|
| FHR registers and the RP stops it | |
| Teardown topology | |
