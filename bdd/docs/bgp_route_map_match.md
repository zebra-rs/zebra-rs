# BGP route-map match clauses

## Overview

As a network operator
I want zebra-rs policy-list entries to filter received routes by
All four match types are exercised against an established eBGP session

## Test Topology

```
  ┌─────────────────────────────────────────┐
  │                   br0                   │
  └─────────────┬───────────────┬───────────┘
                │               │
           ┌────┴────┐     ┌────┴────┐
           │   z1    │     │   z2    │
           │ AS65001 │     │ AS65002 │
           │192.168. │     │192.168. │
           │  0.1/24 │     │  0.2/24 │
           └─────────┘     └─────────┘
```

## Config Files

- z1.yaml: AS 65001, advertises 10.0.0.1/32 + 10.0.0.2/32, outbound
- z2-base.yaml: AS 65002, no input policy; baseline that accepts both
- z2-aspath-pass.yaml: input policy `match as-path-set FROM-65001`
- z2-aspath-fail.yaml: input policy `match as-path-set FROM-65999`
- z2-origin-igp.yaml: input policy `match origin igp` — matches
- z2-origin-egp.yaml: input policy `match origin egp` — no route
- z2-med-eq-pass.yaml: input policy `match med-eq 100` — matches.
- z2-med-eq-fail.yaml: input policy `match med-eq 999` — no match.
- z2-med-range-pass.yaml: input policy `match med-ge 50, med-le 200`
- z2-med-range-fail.yaml: input policy `match med-ge 200` — MED=100
- z2-nh-pass.yaml: input policy `match next-hop-set PEER-SUBNET`
- z2-nh-fail.yaml: input policy `match next-hop-set WRONG-SUBNET`

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Setup topology and establish BGP session with MED-stamping policy | |
| match as-path-set accepts routes whose AS_PATH matches the regex | |
| match as-path-set rejects routes whose AS_PATH does not match | |
| match origin igp accepts network-originated routes | |
| match origin egp rejects network-originated (igp) routes | |
| match med-eq accepts routes with the exact MED value | |
| match med-eq rejects routes with a different MED value | |
| match med-ge and med-le accept routes inside the range | |
| match med-ge rejects routes below the floor | |
| match next-hop-set accepts routes whose nexthop is in the prefix-set | |
| match next-hop-set rejects routes whose nexthop is outside the prefix-set | |
| Teardown topology | |
