# BGP allowas-in relaxes the inbound AS_PATH loop check

## Overview

As a network operator
I want `neighbor X allowas-in [count <1-10>|origin]`
So a neighbor can accept routes whose AS_PATH already contains my AS.

## Test Topology

```
   ┌─────────┐  192.168.0.0/24  ┌─────────┐  192.168.1.0/24  ┌─────────┐
   │   z1    │ i1────────────i1 │   z2    │ i2────────────i1 │   z3    │
   │ AS65001 │                  │ AS65002 │                  │ AS65001 │
   │ .0.1    │                  │.0.2 .1.2│                  │ .1.3    │
   └─────────┘                  └─────────┘                  └─────────┘
```

## Notes

z1 originates 10.0.0.1/32. It reaches z2 with AS_PATH "65001", and z2
re-advertises it to z3 with AS_PATH "65002 65001". Because z3 is also
AS 65001, the RFC 4271 inbound loop check drops it — unless z3 has
`allowas-in` configured on the session toward z2.

## Config Files

- z1.yaml / z2.yaml: static line topology, z1 originates 10.0.0.1/32
- z3-base.yaml:    z3 without allowas-in (strict loop check)
- z3-allowas.yaml: z3 with bare `allowas-in` (default count 3)
- z3-origin.yaml:  z3 with `allowas-in origin`

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Setup line topology and establish all sessions | |
| Default RFC 4271 loop check drops the route at z3 | |
| allowas-in lets z3 accept the looped route | |
| allowas-in origin mode accepts the route and shows in neighbor output | |
| Teardown topology | |
