# BGP IPv4 Labeled-Unicast (SAFI 4) withdraw/peer-down through a sharded daemon

## Overview

Companion to @bgp_shard_v6 for the SAFI-4 (labeled-unicast) Loc-RIB.
Like v6-unicast, LU has no Adj-RIB-Out, so `route_labelv4_withdraw` must
drop a no-op withdraw (one that removed nothing) before re-advertising —
otherwise two speakers that both lack the prefix bounce MP_UNREACH
forever, the same ping-pong fixed for v6-unicast. z2 runs with 4 shards
(LU runs in-process at every N; the shards exercise the exact daemon
configuration that first surfaced the v6 withdraw storm).
A two-node z1—z2 topology is enough: z1 originates two LU prefixes after
the session is Established (z2 ingests them live), and the withdraw of
one of them floods back to z1 (the source), which is where the ping-pong
starts. The withdraw and a peer-down (z1 killed) must each remove exactly
the right routes from z2's LU Loc-RIB.

## Test Topology

```
  z1 (AS65001) ── z2 (AS65002, 4 shards)
  192.168.0.1/24   192.168.0.2/24
```

## Notes

Both on bridge br0. z2's LU Loc-RIB is read directly (LU is in-process,
so the N>1 pooled-`show` gap does not apply here).

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Setup session with z2 sharded, before any routes exist | |
| z1 originates LU routes; the sharded z2 ingests them | |
| z1 withdraws one LU route; the sharded withdraw drops only it | |
| z1's session drops; sharded peer-down sweeps its LU routes | |
| Teardown topology | |
