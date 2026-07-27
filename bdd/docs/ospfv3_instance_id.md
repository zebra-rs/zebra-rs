# OSPFv3 Instance ID separates instances on a link (RFC 5340)

## Overview

As a network operator
I want the per-interface `instance-id` to be stamped into every
OSPFv3 packet header (RFC 5340 §A.3.1) and enforced on receive
(§8.2: drop on mismatch) — so multiple OSPFv3 instances can share
one link without forming cross-instance adjacencies.

## Test Topology

```
    a (10.0.0.1) -- 2001:db8:12::/64 -- b (10.0.0.2)
    matched scenario: both interfaces instance-id 5
    mismatch scenario: a=5, b=7 — no adjacency may form
```

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Matching non-zero instance IDs form a normal adjacency | |
| Mismatched instance IDs never form an adjacency | |
| Teardown topology | |
