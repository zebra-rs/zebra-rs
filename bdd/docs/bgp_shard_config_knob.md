# BGP RIB sharding configured via the router bgp shards YANG knob

## Overview

Validates the C.4 shipping form of RIB sharding: the shard count comes
from config (`router bgp shards <1-64>`, zebra-bgp-sharding.yang) instead
of the `ZEBRA_BGP_SHARDS` environment variable. The sharded device z2 is
started with the PLAIN `start zebra-rs` step — no env var — and gets its
shard count purely from `shards: 4` in its applied config.
Sharding is behavior-transparent (the same correct result at N=1 and
N>1), so a correctness matrix alone cannot prove the knob actually
activated N=4 — it would pass even if the daemon silently fell back to
N=1. The decisive assertion is therefore the startup log line
`BGP RIB sharding: 4 shards (from config)`, emitted by `init_shard_count`
when `spawn_bgp` reads the leaf — which is true only if the knob resolved
to 4 from config. The route-propagation scenario then confirms the
config-sharded daemon ingests and forwards correctly end to end.
The env-driven N>1 read-path matrix (mirror, late-peer sync,
received-routes gather, withdraw, peer-down) is covered by the
bgp_shard_v4_sync feature; this one focuses on the config-knob plumbing.

## Test Topology

```
  z1 (AS65001) ── z2 (AS65002) ── z3 (AS65003)
   10.0.0.1/24    10.0.0.2/24     10.0.0.3/24
   origin         shards: 4       peer
                  (from config)
```

## Notes

All three on bridge br0. z1 originates 10.10.10.0/24 + 10.10.11.0/24.

## Test Scenarios

| Scenario | Result |
|----------|--------|
| z2 is sharded by config (not env) and the speakers establish | |
| routes propagate through the config-sharded z2 | |
| Teardown topology | |
