# OSPFv2 MinLSArrival received-LSA rate limit is configurable

## Overview

As a network operator
I want `router ospf min-ls-arrival` to set the receive-side rate
limit (RFC 2328 §13 MinLSArrival, FRR `timers lsa min-arrival`) —
a flooded LSA instance arriving less than that after the last
accepted copy is discarded without acknowledgement — so I can tune
it away from the fixed 1 s default while the topology still
converges.

## Test Topology

```
    a (10.0.0.1) -- 10.0.12.0/30 -- b (10.0.0.2)
    both routers set min-ls-arrival 2000 ms.
```

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Configured MinLSArrival is applied and the topology still converges | |
| Teardown topology | |
