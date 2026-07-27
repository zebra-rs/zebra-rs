# OSPFv2 adaptive SPF throttle (spf-interval)

## Overview

As a network operator
I want `router ospf spf-interval { initial-wait; secondary-wait;
maximum-wait; }` to configure the IOS-XR-style exponential SPF
hold-down (RFC-style backoff, mirroring zebra-rs IS-IS) instead of
the old fixed 1-second coalescing timer, so a churning area backs
off while a quiet topology still converges quickly.

## Test Topology

```
    a (10.0.0.1) -- 10.0.12.0/30 -- b (10.0.0.2)
    both routers configure spf-interval 100 / 300 / 4000 ms.
```

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Configured throttle is applied and the topology still converges | |
| Teardown topology | |
