# An AddPath path replaced by one the egress refuses is withdrawn (IPv4)

## Overview

As a network operator
I want an AddPath neighbor to lose a path when its replacement may not
be advertised — NO_ADVERTISE, an out-policy deny, an LLGR-stale path
toward a non-LLGR neighbor
So the neighbor does not keep forwarding on the old path forever.

When a path an AddPath neighbor holds is replaced, the replacement goes
out under the same path-id. If the egress refuses the replacement, the
path-id must be withdrawn. For IPv4 unicast, VPNv4 and VPNv6 the AddPath
loop only skipped it, so the neighbor kept the old path. A plain
neighbor gets the withdraw; this feature puts both side by side. The
IPv6 twin (`bgp_addpath_refused_withdraw_v6`) is the control: its
AddPath loop diffs the Adj-RIB-Out and withdraws already.

## Test Topology

```
  ┌──────────────────────────────────────────────────────────────┐
  │                     br0 192.168.60.0/24                      │
  └──────┬───────────────┬───────────────┬───────────────┬───────┘
    ┌────┴────┐     ┌────┴────┐     ┌────┴────┐     ┌────┴────┐
    │   h1    │     │   z1    │     │   z2    │     │   z3    │
    │scripted │     │  (DUT)  │     │ AddPath │     │  plain  │
    │ AS65071 │     │ AS65001 │     │ AS65072 │     │ AS65073 │
    │  .2     │     │  .1     │     │  .3     │     │  .4     │
    └─────────┘     └─────────┘     └─────────┘     └─────────┘
```

## Notes

h1 runs tests/scripts/bgp_attr_inject_send.py and announces 10.60.1.0/24
at session-up. On the trigger file /tmp/bgp_addpath_refused_withdraw.go
it re-announces 10.60.1.0/24 with the NO_ADVERTISE community and, in the
same write, the control prefix 10.60.2.0/24. z1 must advertise
10.60.1.0/24 to nobody after that.

## Config Files

- z1.yaml: DUT — eBGP to h1 (passive), AddPath eBGP to z2, plain eBGP to z3.
- z2.yaml: z1's AddPath neighbor. z3.yaml: z1's plain neighbor.

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Setup topology; z2 and z3 learn the prefix | |
| The NO_ADVERTISE replacement withdraws the path from both neighbors | |
| Teardown topology | |
