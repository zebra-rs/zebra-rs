# OSPFv2 MinLSInterval self-LSA re-origination throttle

## Overview

As a network operator
I want `router ospf min-ls-interval` to bound how often the router
re-originates the same self-LSA (RFC 2328 §12.4 MinLSInterval, FRR
`timers throttle lsa all`), so a burst of topology changes coalesces
into one Router-LSA / Network-LSA update instead of a storm — while
a stable topology still converges.

## Test Topology

```
    a (10.0.0.1) -- 10.0.12.0/30 -- b (10.0.0.2)
    both routers set min-ls-interval 1500 ms.
```

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Configured MinLSInterval is applied and the topology still converges | |
| Teardown topology | |
