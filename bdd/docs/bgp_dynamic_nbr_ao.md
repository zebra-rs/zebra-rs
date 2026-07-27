# A dynamic (listen-range) peer authenticates with TCP-AO (RFC 5925)

## Overview

As a network operator
I want the tcp-ao key-chain on a listen-range's neighbor-group to protect the range
So unconfigured sources cannot open a session just by being in the prefix.

## Test Topology

```
   ┌─────────┐  192.168.0.0/24  ┌─────────┐
   │   z2    │ i1────────────i1 │   z1    │
   │ AS65002 │                  │ AS65001 │
   │ .0.2    │                  │ .0.1    │
   └─────────┘                  └─────────┘
```

## Notes

Requires Linux kernel >= 6.7 on both peers.
The DUT (z1) has no static neighbors: z2 arrives through the
listen-range and inherits SENDERS, which carries the tcp-ao
key-chain. Like the MD5 case, the MKT must be scoped to the whole
prefix — the peer is materialized only after its SYN is accepted,
while the kernel verifies the AO MAC during the handshake.

## Config Files

- z1.yaml:        DUT — SENDERS carries `tcp-ao key-chain BGP-AO`, listen-range 192.168.0.0/24
- z1-noao.yaml:   same DUT with the group's tcp-ao removed
- z1-rotated.yaml: DUT whose BGP-AO chain holds a rotated key-string (same IDs)
- z2.yaml:        client, matching key-chain
- z2-wrong.yaml:  client, mismatched key-string

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Establish a TCP-AO authenticated dynamic session | |
| A mismatched key-string never materializes a peer | |
| Restoring the matching key-string re-establishes the session | |
| Rotating the key-string on the DUT re-keys the prefix MKT | |
| Clearing the group tcp-ao retracts the prefix MKT | |
| Restoring the group tcp-ao re-installs the prefix MKT | |
| Teardown topology | |
