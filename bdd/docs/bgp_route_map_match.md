# BGP route-map match clauses

## Overview

As a network operator
I want zebra-rs policy-list entries to filter received routes by
as-path-set, next-hop-set, MED comparison, and origin, so that
inbound policy can express the same conditions as IOS-XR RPL.
All four match types are exercised against an established eBGP session
by swapping z2's input policy and asserting which advertised prefixes
appear in z2's RIB. z1 attaches an outbound policy that stamps MED=100
on every advertised route so MED match scenarios have something
deterministic to compare against.
Re-evaluation relies entirely on the policy-change trigger
(PolicyRx -> soft-in): applying a config whose policy content changed
re-runs the inbound policy over the Adj-RIB-In. Deliberately NO
`I clear namespace ... neighbor` steps here — that step is an egress
soft-clear (since PR #1318/#1320) and adds nothing to an inbound
policy test; the apply trigger is the path under test.
History: the MED scenarios were broken from the start — the configs
used flat `med-eq:`/`med-ge:`/`med-le:` keys that do not exist in
the schema (the YANG models a one-of `med: { eq | le | ge }`
choice), and the YAML apply silently dropped unknown keys, leaving
IN-MED permit-all. The configs now use the nested shape, and apply
rejects unknown document keys loudly.

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
- z2-med-eq-pass.yaml: input policy `match med eq 100` — matches.
- z2-med-eq-fail.yaml: input policy `match med eq 999` — no match.
- z2-med-range-pass.yaml: input policy `match med le 200` —
- z2-med-range-fail.yaml: input policy `match med ge 200` — MED=100
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
| match med eq accepts routes with the exact MED value | |
| match med eq rejects routes with a different MED value | |
| match med le accepts routes at or below the ceiling | |
| match med ge rejects routes below the floor | |
| match next-hop-set accepts routes whose nexthop is in the prefix-set | |
| match next-hop-set rejects routes whose nexthop is outside the prefix-set | |
| Teardown topology | |
