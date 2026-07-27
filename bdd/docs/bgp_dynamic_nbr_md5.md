# A dynamic (listen-range) peer authenticates with TCP MD5 (RFC 2385)

## Overview

As a network operator
I want the password on a listen-range's neighbor-group to protect the range
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

The DUT (z1) has no static neighbors: z2 arrives through the
listen-range and inherits SENDERS, which carries the password.

This needs a listener key scoped to the whole *prefix*, not to a peer
address: a dynamic peer does not exist until its SYN is accepted, but
the kernel validates the MD5 option during the handshake — so the
per-address key used for static peers can never be installed in time.
A mismatch is therefore invisible at the BGP layer: the kernel drops
the SYN, no peer is ever materialized, and the DUT logs nothing.

## Config Files

- z1.yaml:        DUT — SENDERS carries `password`, listen-range 192.168.0.0/24
- z1-nopass.yaml: same DUT with the group password removed
- z2.yaml:        client, matching tcp-md5 password
- z2-wrong.yaml:  client, mismatched tcp-md5 password

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Establish an MD5-authenticated dynamic session | |
| A mismatched password never materializes a peer | |
| Restoring the matching password re-establishes the session | |
| Clearing the group password retracts the prefix key | |
| Restoring the group password re-installs the prefix key | |
| Teardown topology | |
