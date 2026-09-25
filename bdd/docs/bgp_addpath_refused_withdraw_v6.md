# An AddPath path replaced by one the egress refuses is withdrawn (IPv6)

## Overview

As a network operator
I want an AddPath neighbor to lose a path when its replacement may not
be advertised — NO_ADVERTISE, an out-policy deny, an LLGR-stale path
toward a non-LLGR neighbor
So the neighbor does not keep forwarding on the old path forever.

When a path an AddPath neighbor holds is replaced, the replacement goes
out under the same path-id. If the egress refuses the replacement, the
path-id must be withdrawn. The IPv4 twin (`bgp_addpath_refused_withdraw`)
pins IPv4 unicast, whose AddPath loop only skipped it; this IPv6 twin
is the control — the IPv6-unicast AddPath loop diffs the Adj-RIB-Out
and withdraws the path-id already.

## Test Topology

```
  ┌──────────────────────────────────────────────────────────────┐
  │                     br0 192.168.61.0/24                      │
  └──────┬───────────────┬───────────────┬───────────────┬───────┘
    ┌────┴────┐     ┌────┴────┐     ┌────┴────┐     ┌────┴────┐
    │   h1    │     │   z1    │     │   z2    │     │   z3    │
    │scripted │     │  (DUT)  │     │ AddPath │     │  plain  │
    │ AS65071 │     │ AS65001 │     │ AS65072 │     │ AS65073 │
    │  .2     │     │  .1     │     │  .3     │     │  .4     │
    └─────────┘     └─────────┘     └─────────┘     └─────────┘
```

## Notes

h1 runs tests/scripts/bgp_attr_inject_send.py and announces 2001:db8:60:1::/64
at session-up. On the trigger file /tmp/bgp_addpath_refused_withdraw_v6.go
it re-announces 2001:db8:60:1::/64 with the NO_ADVERTISE community and, in the
same write, the control prefix 2001:db8:60:2::/64. z1 must advertise
2001:db8:60:1::/64 to nobody after that.

## Config Files

- z1.yaml: DUT — eBGP to h1 (passive), AddPath eBGP to z2, plain eBGP to z3;
  IPv6 unicast over IPv4 sessions.
- z2.yaml: z1's AddPath neighbor. z3.yaml: z1's plain neighbor.

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Setup topology; z2 and z3 learn the prefix | |
| The NO_ADVERTISE replacement withdraws the path from both neighbors | |
| Teardown topology | |
