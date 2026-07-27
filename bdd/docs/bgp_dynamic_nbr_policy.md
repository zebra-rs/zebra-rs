# A dynamic (listen-range) peer inherits its neighbor-group's route policy

## Overview

As a network operator
I want the `policy` bound on a listen-range's neighbor-group
So every peer materialized from that range is filtered like a static member.

## Test Topology

```
   ┌─────────┐  192.168.0.0/24  ┌─────────┐
   │   z2    │ i1────────────i1 │   z1    │
   │ AS65002 │                  │ AS65001 │
   │ .0.2    │                  │ .0.1    │
   └─────────┘                  └─────────┘
```

## Notes

z1 (the DUT) has no static neighbors; z2 arrives via the listen-range
and inherits SENDERS. With SENDERS carrying `policy in DENY-ALL` the
session must still establish, z1's own route must still flow out —
but z2's route must be denied on ingress. Rebinding the group without
the policy and re-materializing the peer readmits the route, proving
the policy is resolved from the group at accept time, not baked in.

## Config Files

- z1-deny.yaml: DUT — SENDERS has `policy in DENY-ALL`, originates 10.0.1.1/32
- z1-open.yaml: identical but the group carries no policy binding
- z2.yaml:      client, static neighbor to .0.1, originates 10.0.2.2/32

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Establish with an inbound deny-all policy inherited from the group | |
| Unbinding the group policy readmits the route on re-materialization | |
| Teardown topology | |
