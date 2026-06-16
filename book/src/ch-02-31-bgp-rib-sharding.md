# BGP RIB Sharding

On a single core, BGP route processing — receive an UPDATE, run inbound
policy, re-elect the best path, install to the FIB, run outbound policy,
encode the advertisement — is a serial pipeline. For a large table that one
core is the convergence ceiling: it does not matter how many CPUs the box
has. **RIB sharding** lifts that ceiling for the dominant case by fanning
plain IPv4-unicast route processing across **N worker threads**, each owning
a disjoint slice of the prefix space (chosen by a hash of the prefix), so
ingest, best-path, and egress for different prefixes run in parallel.

It is **off by default** (one shard, the original synchronous path) and
enabled with a single global knob, `router bgp shards <1-64>`.

## When you need it

Sharding helps exactly when single-core best-path is the bottleneck on a
multi-core box:

- a **route reflector** or large transit speaker holding a full table (or
  several), where many peers feed overlapping prefixes and the speaker
  spends its time re-electing best paths and re-advertising;
- initial-convergence or churn storms where UPDATE ingest, not the network,
  is the limiter.

It does **not** help — and adds needless threads — on a small edge router, a
single-peer box, or a workload bounded by the network rather than by CPU.
When in doubt, leave it at the default of `1` and turn it up only after a
measurement shows BGP pinning one core.

## What gets sharded

Only **plain IPv4-unicast** is pooled. At `shards > 1` the speaker spawns N
dedicated worker threads and hashes each IPv4-unicast prefix to one of them;
that worker owns the prefix's Adj-RIB-In and Loc-RIB entry and does its
best-path and egress work. IPv6-unicast, VPNv4/VPNv6, EVPN, and
labeled-unicast continue to run on the main task regardless of the shard
count — so a v6-heavy or VPN-heavy deployment sees little benefit today.

Forwarding correctness is unaffected at any shard count: sharding changes
*where* the work runs, not *what* gets advertised or installed. `show bgp
ipv4`, session-up sync, and `show bgp neighbors <peer> received-routes` all
read the same routes whether you run 1 shard or 16.

A note on core budget: the worker shards and the outbound-policy worker pool
share the machine's cores (the daemon splits them roughly
`max(1, cores − shards)`). More shards is therefore **not** monotonically
better — past a handful, shards start competing with the egress workers for
the same CPUs. **Start at 4** and measure; raising it to the core count is
usually counter-productive.

## Configuration

`shards` is a single global leaf under `router bgp`, valid range `1..64`,
default `1`:

```yaml
router:
  bgp:
    global:
      as: 65001
      router-id: 10.0.0.1
    shards: 4
    neighbor:
    - remote-address: 10.0.0.2
      remote-as: 65002
      enabled: true
      afi-safi:
      - name: ipv4
        enabled: true
```

The equivalent CLI form is:

```
set router bgp shards 4
```

### Startup-only

The shard count is **fixed when the BGP instance starts** (the worker pool
is created before any route state exists). It cannot be changed on a running
instance: resizing the pool would mean re-hashing and migrating the entire
RIB across threads, which is out of scope. If you change `shards` on a live
instance the new value is **ignored with a warning** —

```
router bgp shards 8 ignored: the shard count is fixed at 4 for the BGP
instance lifetime — clear `router bgp` or restart the daemon to re-shard
```

— so to actually re-shard you must remove `router bgp` (which tears the
instance down) and re-add it, or restart the daemon. Set `shards` in the
same commit that first brings up `router bgp`, or in the startup config, and
it takes effect immediately.

### Environment-variable fallback

The pre-config form, the `ZEBRA_BGP_SHARDS` environment variable, still
works and is the **fallback** when the `shards` leaf is unset. Precedence is
**config leaf → `ZEBRA_BGP_SHARDS` → `1`**; the chosen value is clamped to
`1..64`. The config knob is the supported shipping form; the environment
variable remains for test harnesses and scripted runs.

## Verification

At instance start the daemon logs the resolved degree and where it came
from:

```
BGP RIB sharding: 4 shards (from config)
```

The `(from ...)` source is one of `config`, `ZEBRA_BGP_SHARDS`, or
`default`. A single shard logs the synchronous form:

```
BGP RIB sharding: 1 shard, synchronous (from default)
```

This line is the authoritative confirmation that the knob took effect —
because sharding is behavior-transparent, the routing tables themselves look
identical at any shard count, so the log is how you tell `shards: 4`
actually spawned four workers rather than silently falling back to one.

## Egress model: per-peer task (experimental)

Where `shards` parallelises the **ingress** side (which thread elects the
best path), a second, independent knob — `peer-task` — chooses how the
**egress** side is structured.

By default zebra-rs coalesces outbound work into **update groups**: peers
that share an outbound identity (same out-policy, next-hop treatment, AS,
capabilities) are served by one group, so a prefix is policy-processed and
encoded **once** and the resulting bytes are fanned to every member. This is
the FRR model and is the right default — especially for a **route
reflector**, where hundreds of clients often share one policy and would
otherwise each repeat the same encode.

`router bgp peer-task true` switches plain IPv4-unicast egress to a
**per-peer egress task** instead: one task per established peer builds and
encodes that peer's stream independently (the GoBGP per-peer model). This
trades coalescing away for per-peer parallelism — it can help when peers
have *divergent* policies (so update groups wouldn't coalesce much anyway)
and there are spare cores, but for the shared-policy reflector case it
multiplies encode work and is a net loss. It is therefore **experimental and
off by default**; leave it off unless you are specifically measuring the
per-peer model.

```yaml
router:
  bgp:
    global:
      as: 65001
      router-id: 10.0.0.1
    shards: 4
    peer-task: true
```

```
set router bgp peer-task true
```

Like `shards`, `peer-task` is **startup-only** — the two egress models are
alternatives that are never interleaved, so the choice is frozen when the
instance starts. Changing it on a live instance is ignored with a warning;
clear `router bgp` or restart to switch. It supersedes the
`ZEBRA_BGP_PEER_TASK` environment variable (the fallback when the leaf is
unset), and the resolved model is logged at startup:

```
BGP per-peer egress task: enabled (from config)
```

(or `disabled (from default)` for the update-group default). As with the
shard count, this log line is the authoritative confirmation the knob took
effect.
