# BGP match as-path-set with FRR-compatible regular expressions

## Overview

As a network operator
I want zebra-rs `match as-path` to accept the same AS-path regular
expressions as FRR's `bgp as-path access-list`, so that policies port
between the two routers unchanged.

The AS-path regex engine mirrors FRR's `bgp_regcomp`
(bgpd/bgp_regex.c): the `_` magic character expands to
`(^|[,{}() ]|$)`, matching a separator, the start, or the end of the
path. Regexes run against the AS_PATH rendered exactly like FRR's
`aspath->str` (space-separated ASNs; AS_SET members comma-separated).
This feature exercises exact anchored matching plus the three classic
`_` idioms — neighbor-is (`^ASN_`), originates-from (`_ASN$`), and
transits (`_ASN_`).

Re-evaluation rides the policy-change trigger (PolicyRx -> soft-in):
applying a config whose as-path-set/policy changed re-runs the inbound
policy over the Adj-RIB-In — no `clear` needed.

## Test Topology

Linear eBGP chain, all three routers on one L2 segment. z1 and z3 are
never peered, so z1's prefixes reach z3 only via the transit AS z2 and
arrive with AS_PATH `65002 65001`.

```
  ┌──────────────────────────────────────────────────┐
  │                        br0                        │
  └───────┬───────────────┬───────────────┬───────────┘
          │               │               │
     ┌────┴────┐     ┌────┴────┐     ┌────┴────┐
     │   z1    │────▶│   z2    │────▶│   z3    │
     │ AS65001 │     │ AS65002 │     │ AS65003 │
     │ .0.1/24 │     │ .0.2/24 │     │ .0.3/24 │
     └─────────┘     └─────────┘     └─────────┘
```

## Config Files

- z1.yaml: AS 65001, advertises 10.0.0.1/32 + 10.0.0.2/32 to z2.
- z2.yaml: AS 65002, transit; peers z1 and z3, no policy.
- z3-base.yaml: AS 65003, no input policy; both prefixes accepted.
- z3-exact-pass.yaml: `^65002 65001$` — exact whole-path match.
- z3-exact-fail.yaml: `^65001 65002$` — right ASNs, wrong order.
- z3-origin-pass.yaml: `_65001$` — originated by 65001.
- z3-origin-fail.yaml: `_65003$` — 65003 is not on the received path.
- z3-neighbor-pass.yaml: `^65002_` — leftmost (neighbor) AS is 65002.
- z3-transit-fail.yaml: `_65099_` — 65099 is nowhere in the path.

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Setup topology and establish the eBGP chain | |
| exact match accepts the whole AS_PATH anchored with ^ and $ | |
| exact match rejects the same ASNs in the wrong order | |
| _ASN$ accepts routes originated by that AS | |
| _ASN$ rejects routes not originated by that AS | |
| ^ASN_ accepts routes whose neighbor (leftmost) AS matches | |
| _ASN_ rejects routes that do not transit that AS | |
| Teardown topology | |
