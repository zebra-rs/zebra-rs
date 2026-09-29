# A BGP router-id change reaches the neighbors (IPv6)

## Overview

As a network operator
I want a change of the BGP router-id — configured, or the RIB-derived
`system router-id` — to reach every established neighbor
So each neighbor knows us by the identifier our loop checks now use.

A neighbor learns our BGP Identifier only from our OPEN. A router-id
change used to leave every established session on the old identifier
("the next OPEN picks up the new one"), while our own checks moved to
the new one: a route of ours a reflector sends back carries the old
identifier as ORIGINATOR_ID and passed the inbound loop check. The
session is now reset, as FRR, IOS and Junos do. The twin is
`bgp_router_id_change`; this one runs over an IPv6 session.

## Test Topology

```
  ┌─────────────────────────────────────┐
  │        br0 2001:db8:31::/64         │
  └───────┬─────────────────────┬───────┘
     ┌────┴────┐           ┌────┴────┐
     │   z1    │── iBGP ───│   z2    │
     │ AS65000 │           │ AS65000 │
     │ ::1     │           │ ::2     │
     └─────────┘           └─────────┘
```

## Notes

z1 takes its router-id from `system router-id` (192.168.31.1), then
from a changed one (192.168.31.21), then from a configured
`router bgp global router-id` (192.168.31.11), and back. z2 reads the
identifier z1 sent in its OPEN off `show bgp neighbor`.

## Config Files

- z1.yaml: `system router-id 192.168.31.1`; iBGP to z2, no BGP router-id.
- z2.yaml: router-id 192.168.31.2; iBGP to z1.

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Setup; z2 knows z1 by its system router-id | |
| A changed system router-id reaches z2 | |
| A configured BGP router-id reaches z2 | |
| Deleting the configured BGP router-id falls back to the system one | |
| Teardown topology | |
