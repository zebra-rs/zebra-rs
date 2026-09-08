# Withdrawing a route from its source member must not clobber a group-mate's pending advertisement (IPv4)

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

IPv4 twin — the CONTROL: the IPv4 batch withdraw already carries the
guard (`per_peer_suppress`), so this feature is expected to pass before
and after the IPv6 fix. It pins the behaviour the IPv6 family must match.

## Test Topology

```
  ┌───────────────────────────────────────────────────────┐
  │                          br0                          │
  └────┬──────────────┬──────────────┬──────────────┬─────┘
   ┌───┴───┐      ┌───┴───┐      ┌───┴───┐      ┌───┴───┐
   │  z2   │      │  z3   │      │  z1   │      │  z4   │
   │client │      │client │      │  RR   │      │ eBGP  │
   │   .2   │      │   .3   │      │   .1   │      │   .4   │
   └───────┘      └───────┘      └───────┘      └───────┘
```

## Notes

Session addresses are 192.168.80.N; router-ids 10.80.0.N. z2 and z3 are
clients of z1 and share its local address, so they sit in one
update-group with z2 as the lower-index member.

- z4 (eBGP, AS 65002) originates 10.80.5.0/24; z1 reflects it to z2 and
  z3, which both hold it with next-hop 192.168.80.4.
- z3 then originates 10.80.5.0/24 itself. Its empty AS_PATH beats z4's
  one-hop path, so z1's best flips to z3's path: z2 must be advertised
  the prefix with next-hop 192.168.80.3, while z3 — the source — is
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
