# BGP inbound policy through the RIB shards (ZEBRA_BGP_SHARDS>1)

## Overview

As a network operator running BGP with the RIB partitioned across
worker shards (ZEBRA_BGP_SHARDS>1), I want per-neighbor inbound policy
to be applied by the shard workers exactly as on the synchronous N=1
path, so that sharding stays transparent to policy.
This exercises RIB sharding Phase C + PolicyReplace + the dropped N=1
par_iter: z2 runs with 4 shards, so its inbound policy is replicated to
every shard (a peer's prefixes hash across all of them) and applied in
`compute_policy` on the shard worker — not on the main task.
Correctness is observed DOWNSTREAM on z3 on the N>1 advertise,
withdraw, peer-down, and soft-reconfig paths (the N>1 `show` and
new-peer sync are still gaps): policy is set at startup, z3 is brought
up FIRST, and z1's routes are originated only AFTER every session is
Established, so z2 processes them live (ingest → shard → reduce →
advertise to the already-up z3). One inbound policy permits 10.0.0.1/32
and implicit-denies 10.0.0.2/32 — a positive and a negative control in
one shot: z3 must see .1 (sharded permit + advertise works) but never
.2 (sharded deny works; before PolicyReplace the shard default-permitted
and .2 would have leaked).
Follow-on scenarios exercise churn at N=4: a soft-reconfig replay (z2's
prefix-set widens to also permit .2 → SoftInV4 to every pool shard
replays the stored Adj-RIB-In, no UPDATE from z1), an explicit withdraw
(z1 deletes its `network` statements → z2 runs WithdrawV4 to the owning
pool shard), and a session drop (z1 killed → z2's route_clean dispatches
PeerDown to every pool shard) — verified by z3 gaining .2, then losing
10.0.0.1/32.

## Test Topology

```
  z1 (AS65001) ── z2 (AS65002, 4 shards) ── z3 (AS65003)
  192.168.0.1/24   192.168.0.2/24           192.168.0.3/24
```

## Notes

All three on bridge br0.

## Config Files

- z1-base.yaml: AS 65001, peers z2, originates nothing yet.
- z1-routes.yaml: adds network 10.0.0.1/32 + 10.0.0.2/32 (originated
- z2.yaml: AS 65002, peers z1 (inbound policy IN-POL permitting only
- z3.yaml: AS 65003, peers z2 — the downstream observer (N=1, `show`

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Setup sessions with z2 sharded, before any routes exist | |
| z1 originates routes; sharded inbound policy permits .1, denies .2 | |
| z2's inbound prefix-set widens; soft-reconfiguration replays the sharded Adj-RIB-In | |
| z1 withdraws its routes; the sharded withdraw reaches z3 | |
| z1's session drops; sharded peer-down withdraws its routes from z3 | |
| Teardown topology | |
