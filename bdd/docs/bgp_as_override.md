# BGP as-override rewrites the peer AS on egress so a shared-AS neighbor accepts the route

## Overview

As a network operator
I want `neighbor X as-override`
So a neighbor that reuses an AS already in the AS_PATH still accepts my routes.

## Test Topology

```
   ┌─────────┐  192.168.0.0/24  ┌─────────┐  192.168.1.0/24  ┌─────────┐
   │   z1    │ i1────────────i1 │   z2    │ i2────────────i1 │   z3    │
   │ AS65001 │                  │ AS65002 │                  │ AS65001 │
   │ .0.1    │                  │.0.2 .1.2│                  │ .1.3    │
   └─────────┘                  └─────────┘                  └─────────┘
```

## Notes

z1 originates 10.0.0.1/32. It reaches z2 with AS_PATH "65001". When z2
re-advertises it to z3 it would normally prepend its own AS, giving
"65002 65001"; because z3 is also AS 65001 the RFC 4271 loop check
drops it. With `as-override` on z2's session toward z3, z2 first
rewrites z3's AS (65001) in the path to its own (65002), so z3 sees
"65002 65002" and accepts the route. This is the send-side counterpart
to `allowas-in`.

## Config Files

- z1.yaml:           z1 originates 10.0.0.1/32
- z3.yaml:           z3 plain (strict loop check, no allowas-in)
- z2-base.yaml:      z2 without as-override
- z2-override.yaml:  z2 with `as-override` toward 192.168.1.3

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Setup line topology and establish all sessions | |
| Without as-override the RFC 4271 loop check drops the route at z3 | |
| as-override rewrites z3's AS on egress so z3 accepts the route | |
| Teardown topology | |
