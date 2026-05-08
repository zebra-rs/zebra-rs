# BGP reacts to live prefix-set / policy edits without session reset

## Overview

As a network operator
I want zebra-rs to re-evaluate Adj-RIB-In when a referenced prefix-set
or policy-list is edited, so that operational changes propagate
immediately without me having to clear the BGP session.
The exercise: z2 attaches `apply-policy in HOGE`, where policy HOGE
matches `prefix-set HOGE`. Because the prefix-set is referenced
*indirectly* via the policy's match clause, the harness must follow
the cascade prefix-set HOGE -> policy HOGE -> peer's Adj-RIB-In
every time the prefix-set is edited. Without the cascade, BGP would
only see the change after a manual `clear ... soft in`.

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

- z1.yaml: AS 65001, advertises 1.1.1.1/32 + 2.2.2.2/32, no policy.
- z2-initial.yaml: prefix-set HOGE = { 1.1.1.1/32 }; policy HOGE matches
- z2-both.yaml: prefix-set HOGE = { 1.1.1.1/32, 2.2.2.2/32 } (added).
- z2-other.yaml: prefix-set HOGE = { 2.2.2.2/32 } (1.1.1.1/32 removed).

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Setup topology and verify initial filter | |
| Adding a prefix to the referenced prefix-set propagates without session reset | |
| Removing a prefix from the referenced prefix-set withdraws the corresponding route | |
| Teardown topology | |
