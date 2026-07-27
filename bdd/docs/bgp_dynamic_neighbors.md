# BGP dynamic neighbors materialize passive peers from a listen-range

## Overview

As a network operator
I want `router bgp dynamic-neighbors listen-range <prefix> neighbor-group <G>`
So sessions from an authorized source prefix establish without per-peer config.

## Test Topology

```
   ┌─────────┐  192.168.0.0/24  ┌─────────┐  192.168.1.0/24  ┌─────────┐
   │   z2    │ i1────────────i1 │   z1    │ i2────────────i1 │   z3    │
   │ AS65002 │   (in range)     │ AS65001 │  (out of range)  │ AS65002 │
   │ .0.2    │                  │.0.1 .1.1│                  │ .1.3    │
   └─────────┘                  └─────────┘                  └─────────┘
```

## Notes

z1 has NO static neighbors. Its listen-range 192.168.0.0/24 binds
neighbor-group SENDERS (remote-as 65002, ipv4 enabled), so z2's inbound
connection materializes a passive peer that must reach Established and
exchange routes in both directions (regression pin for PR #2044, where
the materialized peer was left in Idle and every connection was
dropped). z3 runs the same client config from 192.168.1.3 — outside
the range — and must be refused at accept time with no peer state.
`listen-limit` is 1 on the DUT, so every re-establishment below also
proves the freed slot was actually returned — a leaked slot saturates
the cap and the client can never reconnect.

## Config Files

- z1.yaml:         DUT — group SENDERS + listen-range 192.168.0.0/24, originates 10.0.1.1/32
- z1-norange.yaml: same DUT with the listen-range deleted (group kept)
- z2.yaml:         in-range client, static neighbor to .0.1, originates 10.0.2.2/32
- z3.yaml:         out-of-range client, static neighbor to .1.1, originates 10.0.3.3/32

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Setup topology and establish the dynamic session | |
| Routes flow in both directions over the dynamic session | |
| A source outside every listen-range is refused without peer state | |
| The client can hard-reset and re-establish the dynamic session | |
| A DUT-side clear frees the peer and the next connect re-materializes it | |
| Deleting the listen-range revokes the peers it materialized | |
| Restoring the listen-range re-materializes the peer in the freed slot | |
| Teardown topology | |
