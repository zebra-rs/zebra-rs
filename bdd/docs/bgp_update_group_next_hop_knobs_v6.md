# Per-neighbor next-hop knobs must shard the IPv6-unicast update-group (IPv6)

## Overview

As a network operator
I want `afi-safi ipv6 next-hop-self` and `afi-safi ipv6 next-hop-unchanged`
to take effect per neighbor even when several neighbors share one
update-group
So that a reflector or an IXP router whose neighbors sit on one segment
sends each of them the next-hop its own configuration asks for.

IPv6 twin of `bgp_update_group_next_hop_knobs`: the IPv6-unicast
advertise path reads the per-neighbor knobs straight from the peer,
but the update-group signature carried only their VPNv4 twins, so two
neighbors that differ only in a knob shared one memoized canonical
UPDATE and the lower-index member decided the NEXT_HOP for both.

The knob placement is MIRRORED relative to the IPv4 feature: here the
canonical (lower-address) member of each pair is the one WITHOUT the
knob, so it is the knob-bearing neighbor that is handed the wrong
next-hop — the opposite direction of the same defect.

## Test Topology

```
  ┌───────────────────────────────────────────────────────────────────┐
  │                               br0                                 │
  └────┬──────────────┬──────────────┬──────────────┬──────────────┬──┘
   ┌───┴───┐      ┌───┴───┐      ┌───┴───┐      ┌───┴───┐      ┌───┴───┐
   │  z2   │      │  z3   │      │  z1   │      │  z4   │      │  z5   │
   │ iBGP  │      │ iBGP  │      │  DUT  │      │ eBGP  │      │ eBGP  │
   │ plain │      │nh-self│      │ 65001 │      │nh-unch│      │ 65003 │
   │  ::2  │      │  ::3  │      │  ::1  │      │  ::4  │      │  ::5  │
   └───────┘      └───────┘      └───────┘      └───────┘      └───────┘
```

## Notes

Session addresses are 2001:db8:60::N; router-ids 10.61.0.N. The knobs
are on z1: `next-hop-self` toward z3, `next-hop-unchanged` toward z4.

- z4 (eBGP) originates 2001:db8:40::/64; z1 forwards it to z2 and z3.
  z2 must keep next-hop 2001:db8:60::4, z3 must see 2001:db8:60::1 (self).
- z2 (iBGP) originates 2001:db8:20::/64; z1 forwards it to z4 and z5.
  z4 must keep 2001:db8:60::2, z5 must see 2001:db8:60::1 (eBGP default).

The prefixes are injected only after every session is Established, so
every advertisement takes the event-driven (memoized) path and not the
per-peer session-up dump.

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
| The plain iBGP neighbor keeps the eBGP next-hop (control) | |
| The iBGP neighbor with next-hop-self in the same update-group receives z1 as the next-hop | |
| The eBGP neighbor with next-hop-unchanged keeps the originator's next-hop (control) | |
| The plain eBGP neighbor in the same update-group receives z1 as the next-hop | |
| Each next-hop knob puts its neighbor in its own IPv6-unicast update-group | |
| Teardown topology | |
