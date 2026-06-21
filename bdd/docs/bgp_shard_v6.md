# BGP IPv6-unicast Loc-RIB through the RIB shards (ZEBRA_BGP_SHARDS>1)

## Overview

The IPv6 mirror of @bgp_shard_policy. With the RIB partitioned across
worker shards (ZEBRA_BGP_SHARDS>1), IPv6-unicast routes must flow
through the pool exactly as IPv4-unicast does — ingest → owning shard →
reduce → advertise — and the churn paths (withdraw, peer-down) must hit
the pool too, not the now-empty synchronous shard.
z2 runs with 4 shards. Correctness is observed DOWNSTREAM on z3 (N=1,
so its `show` reads a whole table): z1 originates a v6 prefix only after
every session is Established, so z2 processes it live on the N>1 path.
IPv6 inbound policy still runs in main (the post-policy decision is sent
to the shard), so this first cut does not exercise sharded policy /
soft-reconfig — those land with full v4/v6 parity (compute-policy +
SoftInV6) as a follow-up, mirrored from @bgp_shard_policy.

## Test Topology

```
  z1 (AS65001) ── z2 (AS65002, 4 shards) ── z3 (AS65003)
  2001:db8::1/64   2001:db8::2/64           2001:db8::3/64
```

## Notes

All three on bridge br0.

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Setup sessions with z2 sharded, before any routes exist | |
| z1 originates v6 routes; the sharded z2 advertises them to z3 | |
| z1 withdraws one v6 route; the sharded withdraw reaches z3 | |
| z1's session drops; sharded peer-down withdraws its v6 routes from z3 | |
| Teardown topology | |
