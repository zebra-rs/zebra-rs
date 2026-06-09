# BGP enforce-first-as drops inbound updates whose AS_PATH does not start with the peer AS

## Overview

As a network operator
I want `neighbor X enforce-first-as`
So a peer that forwards routes without prepending its own AS first is not trusted.

## Test Topology

```
   ┌─────────┐  192.168.0.0/24  ┌─────────┐
   │   z1    │ i1────────────i1 │   z2    │
   │ AS65001 │                  │ AS65002 │
   │  .0.1   │                  │  .0.2   │
   └─────────┘                  └─────────┘
   originates 10.0.0.1/32
```

## Notes

z1 originates 10.0.0.1/32. It also runs an outbound route-map toward z2
that prepends a *foreign* AS (65099). zebra-rs applies the mandatory
eBGP local-AS prepend first ("65001"), then the route-map prepend lands
65099 left-most, so z2 receives AS_PATH "65099 65001". The left-most AS
is 65099, not z1's own AS 65001.
Normally z2 accepts that route (AS 65002 is not in the path, so there is
no loop). With `enforce-first-as` on z2's session toward z1, z2 instead
requires the left-most AS to be the peer's own AS (65001) and discards
the update because it starts with 65099.

## Config Files

- z1.yaml:          z1 originates 10.0.0.1/32, prepends foreign AS 65099 on egress
- z2-base.yaml:     z2 without enforce-first-as (accepts the route)
- z2-enforce.yaml:  z2 with `enforce-first-as` toward 192.168.0.1

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Setup the topology and establish the session | |
| Without enforce-first-as z2 accepts the foreign-first-AS route | |
| With enforce-first-as z2 drops the route | |
| Teardown topology | |
