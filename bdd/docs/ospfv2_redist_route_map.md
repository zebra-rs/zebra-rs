# OSPFv2 redistribution route-map filters and re-applies dynamically

## Overview

As a network operator
I want `redistribute <source> route-map <name>` to filter and
modify routes entering OSPF as Type-5 AS-External LSAs — and I
want edits to the route-map (or a prefix-set it references) to
re-apply LIVE, originating newly-permitted prefixes and flushing
newly-denied ones without touching the OSPF session.

## Test Topology

```
    r1 -- 10.0.12.0/30 -- r2 (redistribute connected route-map RM)
    r2 dummies (not OSPF-enabled): d1 10.1.1.0/24, d2 10.2.2.0/24
    RM: permit prefix-set PS, set metric 555; implicit deny rest.
```

## Notes

The scenarios share one topology: setup, two live edits, teardown
(mirrors bgp_policy_dynamic_update).

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Setup — route-map admits only the prefix-set, with set metric | |
| Live edit — adding a prefix to the referenced prefix-set originates it | |
| Live edit — removing a prefix flushes its Type-5 LSA | |
| Teardown topology | |
