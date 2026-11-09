# BGP unnumbered neighbor with remote-as external

## Overview

As a network operator running BGP over IPv6-only point-to-point links
I want to configure each `interface-neighbor` with `remote-as external`
So that every fabric link carries the same config and the neighbor's
AS is learned from its OPEN, as FRR's shorthand does.

An `external` neighbor holds the placeholder AS 0 until the OPEN, and
every OPEN is accepted from any AS but ours. Before this was built the
peer never dialed (AS 0 failed the dial gate) and an inbound OPEN
failed the AS check, so a link with `external` on both ends never came
up.

Test Topology (P2P veth, link-local only — no v4/global-v6 addrs on
i1; the LAN prefixes live on dummy interfaces):
```
```

## Config Files

- z1-base.yaml / z2-base.yaml: a bare `router bgp` block, so ND learns
  i1 before RA is enabled (see bgp_unnumbered_neighbor).
- z1-full.yaml / z2-full.yaml: RA on i1, `interface-neighbor i1
  remote-as external`, and the local LAN /24.

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Setup topology | |
| Both ends with remote-as external establish and learn each other's AS | |
| Teardown topology | |
