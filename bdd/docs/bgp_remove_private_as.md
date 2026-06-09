# BGP remove-private-as strips private ASNs from the egress AS_PATH

## Overview

As a network operator
I want `neighbor X remove-private-as`
So a downstream eBGP peer never learns the private internal AS numbers
of my network.

## Test Topology

```
   ┌─────────┐  192.168.0.0/24  ┌─────────┐  192.168.1.0/24  ┌─────────┐
   │   z1    │ i1────────────i1 │   z2    │ i2────────────i1 │   z3    │
   │ AS65001 │                  │ AS 100  │                  │ AS 200  │
   │ .0.1    │                  │.0.2 .1.2│                  │ .1.3    │
   └─────────┘                  └─────────┘                  └─────────┘
   private AS                    public AS                    public AS
```

## Notes

z1 originates 10.0.0.1/32; z2 learns it with AS_PATH "65001". When z2
re-advertises it to z3 it normally prepends its own AS, sending
"100 65001" — leaking z1's private AS 65001 to z3. With
`remove-private-as` on z2's session toward z3, z2 strips the private
65001 before prepending, so z3 receives just "100". The neighbor's own
AS (z3's 200) would always be kept for loop prevention, but here it is
not in the path.

## Config Files

- z1.yaml:          z1 (private AS 65001) originates 10.0.0.1/32
- z3.yaml:          z3 plain
- z2-base.yaml:     z2 without remove-private-as
- z2-remove.yaml:   z2 with `remove-private-as` toward 192.168.1.3

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Setup line topology and establish all sessions | |
| Without remove-private-as the private AS leaks to z3 | |
| remove-private-as strips the private AS on egress to z3 | |
| Teardown topology | |
