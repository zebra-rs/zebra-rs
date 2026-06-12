# BGP neighbor ip-transparent (peer as an address the host does not own)

## Overview

As a network operator
I want a BGP session sourced from an address the host does not own
(`update-source <foreign-addr>`) to stay down by default — the kernel
refuses the non-local bind — and to establish once `ip-transparent`
puts IP_TRANSPARENT on the session socket, confirming the knob
end-to-end (FRR 10.4 `neighbor X ip-transparent`, mirroring its
bgp_tcp_ip_transparent topotest).

## Test Topology

```
  ┌─────────────────────────────────────────┐
  │                   br0                    │
  └─────────────┬───────────────┬───────────┘
                │               │
           ┌────┴────┐     ┌────┴────────────┐
           │   z1    │     │   z2            │
           │ AS65001 │     │ AS65002         │
           │ 10.0.0. │     │ 10.0.0.2/24     │
           │  1/24   │     │ peers AS        │
           │         │     │ 10.255.0.99     │
           │         │     │ (owned by NOBODY)│
           └─────────┘     └─────────────────┘
```

## Notes

z2 dials z1 sourcing the session from 10.255.0.99 — an address that is
configured on no interface anywhere. z1 peers with 10.255.0.99 and has
a static return route toward it via z2's real address. z2 carries the
TPROXY-style return-path policy routing (inbound TCP fwmark → table
100 `local default dev lo`, installed by a harness step) so packets to
the phantom address reach its sockets; the ONLY remaining blocker is
the kernel's non-local bind / source checks, which is precisely what
`ip-transparent` lifts — making it the discriminating knob of the
scenario pair. z1's own active side is held by the eBGP connected
check (10.255.0.99 is not on a connected subnet), so z2 owns the
connect direction.

## Config Files

- z1.yaml: neighbor 10.255.0.99, static return route.
- z2-base.yaml: update-source 10.255.0.99, no ip-transparent.
- z2-transparent.yaml: same, plus `ip-transparent`.

## Test Scenarios

| Scenario | Result |
|----------|--------|
| A non-local update-source keeps the session down without ip-transparent | |
| ip-transparent lets the session establish from the foreign address | |
| Teardown topology | |
