# OSPFv2 redistributes routes from a kernel routing table

## Overview

As a network operator
I want `redistribute table <id>` (FRR parity) to import routes the
kernel holds in a non-main routing table — installed externally
via `ip route ... table N` — as Type-5 AS-External LSAs, tracking
the table live: routes added later originate, deleted ones flush.

## Test Topology

```
    r1 -- 10.0.12.0/30 -- r2 (redistribute table 100, metric 30)
    table 100 on r2 (unicast dev-lo routes): 10.55.1.0/24
    (pre-start, covers the netlink dump path) and 10.55.2.0/24
    (added live, covers the monitor delta path).
```

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Kernel-table routes originate as externals and track live changes | |
| Teardown topology | |
