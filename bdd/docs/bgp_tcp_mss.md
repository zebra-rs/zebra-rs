# BGP TCP MSS (neighbor tcp-mss)

## Overview

As a network operator
I want to cap the TCP Maximum Segment Size of a BGP session so the
daemon stays under a path MTU smaller than the interface MTU (a tunnel,
an MPLS core, a link that cannot carry full-size frames) instead of
stalling on a black-holed large UPDATE.

## Test Topology

```
  ┌─────────────────────────────────────────┐
  │                   br0                    │
  └─────────────┬───────────────┬───────────┘
                │               │
           ┌────┴────┐     ┌────┴────┐
           │   z1    │     │   z2    │
           │ AS65001 │     │ AS65002 │
           │192.168. │     │192.168. │
           │  0.1/24 │     │  0.2/24 │
           └─────────┘     └─────────┘
```

## Config Files

- z1-1.yaml: AS 65001, neighbor 192.168.0.2 with `tcp-mss 500`.
- z2-1.yaml: AS 65002, neighbor 192.168.0.1 with `tcp-mss 500`.

socket and the listening socket, so the kernel negotiates the reduced
MSS. `getsockopt(TCP_MAXSEG)` reads back the negotiated value (the
the 12-byte TCP timestamp option, so a configured 500 syncs to 488.
Both ends must advertise the clamp for both to read it back, which is
why both neighbors set `tcp-mss 500`.

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Session establishes and reports configured and synced tcp-mss | |
| Teardown topology | |
