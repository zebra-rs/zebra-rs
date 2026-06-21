# BGP per-peer egress task configured via the router bgp peer-task knob

## Overview

Validates the shipping form of the per-peer egress task (PET): the egress
model comes from config (router bgp peer-task true, zebra-bgp-sharding.yang)
instead of the ZEBRA_BGP_PEER_TASK environment variable. The device z2 is
started with the PLAIN start step — no env vars — and reads BOTH its shard
count (shards: 4) and its egress model (peer-task: true) from config.
PET runs the v4-unicast egress through a per-peer task (the GoBGP per-peer
model) instead of the main-task update-groups, and is exercised together
with sharding, so z2 sets both knobs. Like sharding, the egress model is
behavior-transparent, so the decisive proof that the knob took effect is
the startup log line BGP per-peer egress task: enabled (from config),
emitted by init_peer_task when spawn_bgp reads the leaf. The
route-propagation scenario then confirms the config-driven PET egress
ingests and forwards end to end.
The env-driven PET matrix is covered by bgp_peer_egress_v4; this feature
focuses on the config-knob plumbing.

## Test Topology

```
  z1 (AS65001) ── z2 (AS65002) ── z3 (AS65003)
   10.0.0.1/24    10.0.0.2/24     10.0.0.3/24
   origin         shards: 4       peer
                  peer-task: true
                  (from config)
```

## Notes

All three on bridge br0. z1 originates 10.10.10.0/24 + 10.10.11.0/24.

## Test Scenarios

| Scenario | Result |
|----------|--------|
| z2 reads both shards and peer-task from config and the speakers establish | |
| routes propagate through the config-driven per-peer egress | |
| Teardown topology | |
