# Per-neighbor next-hop knobs must shard the IPv4-unicast update-group (IPv4)

## Overview

As a network operator
I want `afi-safi ipv4 next-hop-self` and `afi-safi ipv4 next-hop-unchanged`
to take effect per neighbor even when several neighbors share one
update-group
So that a reflector or an IXP router whose neighbors sit on one segment
sends each of them the next-hop its own configuration asks for.

An update-group is keyed by a signature of every per-peer input to the
egress transform; members share one memoized canonical UPDATE. The
IPv4-unicast advertise path honors the per-neighbor next-hop-self and
next-hop-unchanged knobs, but the signature carried only their VPNv4
twins. Two iBGP neighbors that differ only in `next-hop-self` — or two
eBGP neighbors that differ only in `next-hop-unchanged` — therefore
shared a group, and whichever had the lower peer index decided the
NEXT_HOP for both.

## Test Topology

```
  ┌───────────────────────────────────────────────────────────────────┐
  │                               br0                                 │
  └────┬──────────────┬──────────────┬──────────────┬──────────────┬──┘
   ┌───┴───┐      ┌───┴───┐      ┌───┴───┐      ┌───┴───┐      ┌───┴───┐
   │  z2   │      │  z3   │      │  z1   │      │  z4   │      │  z5   │
   │ iBGP  │      │ iBGP  │      │  DUT  │      │ eBGP  │      │ eBGP  │
   │nh-self│      │ plain │      │ 65001 │      │ 65002 │      │nh-unch│
   │  .2   │      │  .3   │      │  .1   │      │  .4   │      │  .5   │
   └───────┘      └───────┘      └───────┘      └───────┘      └───────┘
```

## Notes

Session addresses are 192.168.60.N; router-ids 10.60.0.N. The knobs
are on z1: `next-hop-self` toward z2, `next-hop-unchanged` toward z5.

- z4 (eBGP) originates 10.40.0.0/24; z1 forwards it to z2 and z3.
  z2 must see next-hop 192.168.60.1 (self), z3 must keep 192.168.60.4.
- z2 (iBGP) originates 10.20.0.0/24; z1 forwards it to z4 and z5.
  z4 must see next-hop 192.168.60.1 (eBGP default), z5 must keep
  192.168.60.2.
In each pair the lower-address neighbor is the canonical member of the
wrongly shared group, so the second member of each pair is the one
that received the wrong next-hop.

The prefixes are injected only after every session is Established:
the session-up dump builds each peer's UPDATE on its own, so a route
that arrived before a peer came up would reach it correctly and mask
the defect. Only the event-driven path goes through the shared memo.

## Config Files

- z1.yaml: router under test, the four neighbors and their knobs.
- z2.yaml / z2-network.yaml, z4.yaml / z4-network.yaml: originators,
  session only and with their network.
- z3.yaml, z5.yaml: listeners.

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Setup topology and establish all four sessions before any route exists | |
| Inject the routes once every session is up, so they take the event-driven path | |
| The iBGP neighbor with next-hop-self receives z1 as the next-hop (control) | |
| The plain iBGP neighbor in the same update-group keeps the eBGP next-hop | |
| The plain eBGP neighbor receives z1 as the next-hop (control) | |
| The eBGP neighbor with next-hop-unchanged in the same update-group keeps the originator's next-hop | |
| Each next-hop knob puts its neighbor in its own update-group | |
| Teardown topology | |
