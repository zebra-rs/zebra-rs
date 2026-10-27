# A looped UPDATE in a Clos leaves the spines' routes alone

## Overview

As a network operator running a Clos whose spines share one AS
I want a leaf's looped copy of another leaf's route to change nothing
So the spines and leaves do not reinstall and re-send unchanged routes.

Every leaf route a spine sends to leaf L1 comes back from L1 toward
the other spine with the spines' AS in the AS_PATH. That spine treats
it as a withdraw (RFC 4271 §9.1.2), but it never accepted a path for
the prefix from L1, so nothing is removed and nothing should change.
Before #2599 the spine went on anyway: it reinstalled its unchanged
best in the kernel and re-sent it to its peers, L1 re-sent its own
best to the spine again, and the next looped UPDATE started it over.
With the advertisement interval at 0 that was a continuous loop: the
spines deleted and re-added the leaf loopbacks in the kernel over and
over, and dropped packets while they did.

## Test Topology

```
  ┌──────────────────────────────────────────────────────────────┐
  │                     br0 192.168.61.0/24                      │
  └─────┬──────────────┬────────────────┬──────────────┬─────────┘
   ┌────┴────┐    ┌────┴────┐      ┌────┴────┐    ┌────┴────┐
   │   s1    │    │   s2    │      │   l1    │    │   l2    │
   │ spine   │    │ spine   │      │  leaf   │    │  leaf   │
   │ AS65000 │    │ AS65000 │      │ AS65011 │    │ AS65012 │
   │  .1     │    │  .2     │      │  .11    │    │  .12    │
   └─────────┘    └─────────┘      └─────────┘    └─────────┘
```

## Notes

Each leaf has an eBGP session to each spine; the spines do not peer
with each other, nor the leaves. l1 originates 10.61.0.11/32 and l2
10.61.0.12/32. Every node runs the eBGP advertisement interval at 0,
so a re-send loop would run flat out rather than once per MRAI.

## Config Files

- s1.yaml, s2.yaml: the spines, AS 65000.
- l1.yaml, l2.yaml: the leaves, ECMP over both spines.

tests/scripts/route_churn_count.py watches `ip -o monitor route` in a
namespace for a few seconds and prints `CHURN <n>` if the prefix
changed in the kernel, `quiet` otherwise.

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Setup topology and establish sessions | |
| Every leaf loopback reaches both spines and the other leaf | |
| After convergence the kernel routes stay put | |
| Teardown topology | |
