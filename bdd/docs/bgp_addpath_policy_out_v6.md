# An AddPath neighbor's outbound policy applies to route changes too (IPv6)

## Overview

As a network operator
I want a neighbor's `policy out` to filter and rewrite every IPv6 route
sent to it with AddPath, not only the ones in the session-up dump
So a prefix my policy denies never leaks to that neighbor, and my set
actions are on every UPDATE.

A neighbor that negotiated AddPath send is not in the plain fan-out, so
when a route changes its only advertise path is the AddPath loop. For
IPv6 unicast that loop sent every candidate without running the
outbound policy: a denied prefix was filtered at session-up and leaked
on the first change, and a `set` action was missing from every such
UPDATE. The IPv4 twin (`bgp_addpath_policy_out`) shows the same setup
already works for IPv4.

## Test Topology

```
  ┌─────────────────────────────────────────────────────────┐
  │                   br0 192.168.59.0/24                   │
  └───────┬────────────────────┬────────────────────┬───────┘
     ┌────┴────┐          ┌────┴────┐          ┌────┴────┐
     │   h1    │          │   z1    │          │   z2    │
     │scripted │─eBGP────▶│  (DUT)  │─AddPath─▶│ zebra-rs│
     │ AS65061 │          │ AS65001 │  eBGP    │ AS65062 │
     │  .2     │          │  .1     │          │  .3     │
     └─────────┘          └─────────┘          └─────────┘
```

## Notes

z1 sends IPv6 unicast to z2 with AddPath, through an out-policy that
denies 2001:db8:58:1::/64 and sets MED 50 on everything else. z1 and z2
establish first; only then does h1 (tests/scripts/bgp_attr_inject_send.py)
announce 2001:db8:58:1::/64 and 2001:db8:58:2::/64, so both reach z2
through the route-change path, not the session-up dump.

## Config Files

- z1.yaml: DUT — eBGP to h1 (passive); AddPath eBGP to z2 with the
  out-policy; IPv6 unicast over IPv4 sessions.
- z2.yaml: z1's AddPath neighbor.

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Setup topology; z1 and z2 establish before any route exists | |
| Routes learned after the session is up go through the out-policy | |
| Teardown topology | |
