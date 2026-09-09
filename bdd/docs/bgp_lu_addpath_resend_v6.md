# AddPath labeled-unicast peers must not re-send unchanged candidates to each other (IPv6)

## Overview

As a network operator
I want two routers with AddPath labeled-unicast toward each other to
settle after exchanging their paths
So that they do not re-advertise the same candidates to each other on
every UPDATE, forever, at line rate.

The labeled-unicast AddPath fan-out sends every candidate to every
AddPath peer on every best-path event and only then records it in the
Adj-RIB-Out, discarding what was recorded before — so it cannot tell an
unchanged candidate from a new one (the best-path-only branch does,
via `same_advertised`). With AddPath in both directions and a prefix
both routers hold, each UPDATE received makes the receiver fan its own
candidate back, which makes the sender do the same: a re-send loop
bounded only by the round-trip time.

IPv6 labeled-unicast twin (`label-v6`).

## Test Topology

```
  ┌───────────────────────────────┐
  │              br0              │
  └────┬─────────────────────┬────┘
   ┌───┴───┐             ┌───┴───┐
   │  z1   │   AddPath   │  z2   │
   │ 65001 │ ◄─────────► │ 65002 │
   │  ::1  │  LU both  │  ::2  │
   └───────┘   directions └───────┘
```

## Notes

Session addresses are 2001:db8:90::N; router-ids 10.91.0.N. Both routers
originate 2001:db8:95::/64 in labeled-unicast.

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Setup topology; both routers hold both candidates | |
| The sessions settle instead of re-sending the unchanged candidates forever | |
| Teardown topology | |
