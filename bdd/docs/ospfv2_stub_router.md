# OSPFv2 stub-router advertisement (RFC 6987 max-metric router-lsa)

## Overview

As a network operator
I want `max-metric router-lsa` to advertise my transit links at
MaxLinkMetric (0xFFFF) — administratively for maintenance, or for a
startup grace window — so neighbors route transit traffic around me
while my own prefixes (stub links, normal cost) stay reachable.

## Test Topology

```
    r1 ---10--- r2 ---10--- r3   (via r2: cost 20 — normally wins)
     \---100--- r4 ---100---/    (via r4: cost 200 — the detour)
    r3-lo 10.0.0.3/32; the stub router under test is r2.
```

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Administrative max-metric pushes transit traffic onto the detour | |
| on-startup max-metric expires and normal routing resumes | |
| Teardown topology | |
