# Withdrawing a route from its source member must not clobber a group-mate's pending advertisement (IPv6)

## Overview

As a network operator
I want a reflector whose best path for a prefix flips to a client's own
path to advertise the new path to that client's group-mates
So that the group-mates follow the reflector's selection instead of
keeping a next-hop the reflector no longer prefers.

An update-group shares one pending-advertisement cache. When the best
path for a prefix changes, the batch runs one outcome per member: an
advertisement, queued into the shared cache for the next flush, or a
per-peer withdraw — for the member the new best was learned from
(split-horizon), which is withdrawn what it held before. That withdraw
must leave the shared cache alone: the entry it would remove is the one
just queued for the other members.

The GATE: the IPv6 batch withdraw has no such guard. When the reflector's
best for a prefix flips to a path learned from one client, the batch
queues the new advertisement for the other member of the group and then
runs the source client's per-peer withdraw — which pops that queued
entry out of the group's cache. The other client's Adj-RIB-Out at the
reflector says "via the new source" while the wire still says "via the
old one", and nothing repeats the announcement until the best changes
again; once the old path is gone that client forwards into a hole.

## Test Topology

```
  ┌───────────────────────────────────────────────────────┐
  │                          br0                          │
  └────┬──────────────┬──────────────┬──────────────┬─────┘
   ┌───┴───┐      ┌───┴───┐      ┌───┴───┐      ┌───┴───┐
   │  z2   │      │  z3   │      │  z1   │      │  z4   │
   │client │      │client │      │  RR   │      │ eBGP  │
   │  ::2   │      │  ::3   │      │  ::1   │      │  ::4   │
   └───────┘      └───────┘      └───────┘      └───────┘
```

## Notes

Session addresses are 2001:db8:80::N; router-ids 10.81.0.N. z2 and z3 are
clients of z1 and share its local address, so they sit in one
update-group with z2 as the lower-index member.

- z4 (eBGP, AS 65002) originates 2001:db8:85::/64; z1 reflects it to z2 and
  z3, which both hold it with next-hop 2001:db8:80::4.
- z3 then originates 2001:db8:85::/64 itself. Its empty AS_PATH beats z4's
  one-hop path, so z1's best flips to z3's path: z2 must be advertised
  the prefix with next-hop 2001:db8:80::3, while z3 — the source — is
  withdrawn what it held.
- z4 withdraws the prefix: z2 must still hold it via z3.

## Config Files

- z1.yaml: reflector; z2.yaml, z3.yaml: clients (z3-network.yaml adds
  z3's own prefix); z4.yaml / z4-withdrawn.yaml: the eBGP originator.

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Setup topology; both clients hold the prefix via the eBGP neighbor | |
| The reflector's best flips to z3's own path; z2 must be advertised the new path | |
| The eBGP originator withdraws; z2 keeps the prefix via z3 | |
| Teardown topology | |
