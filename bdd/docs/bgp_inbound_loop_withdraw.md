# A looped replacement withdraws the neighbor's earlier path (IPv4)

## Overview

As a network operator
I want an UPDATE that my AS-path loop check rejects to still withdraw
the path that neighbor sent before for the same prefix
So a neighbor that re-routes through me after losing its own path does
not leave me forwarding to it while it forwards back.

An UPDATE replaces the path its sender advertised before for the same
NLRI (RFC 4271 §3.1). When the replacement carries our AS it is
unusable (RFC 4271 §9.1.2), but the old path is gone too: the neighbor
no longer has it. FRR removes the existing path when it filters the
replacement. zebra-rs dropped the UPDATE and kept the old path, so it
kept routing to the neighbor — which now routes through us — and kept
advertising the path downstream. Neighbors such as FRR send a looped
path back by default, so this needs nothing unusual to happen.

## Test Topology

```
  ┌─────────────────────────────────────────────────────────┐
  │                   br0 192.168.48.0/24                   │
  └───────┬────────────────────┬────────────────────┬───────┘
     ┌────┴────┐          ┌────┴────┐          ┌────┴────┐
     │   h1    │          │   z1    │          │   z2    │
     │scripted │─eBGP────▶│  (DUT)  │─eBGP────▶│ zebra-rs│
     │ AS65061 │          │ AS65060 │          │ AS65062 │
     │  .2     │          │  .1     │          │  .3     │
     └─────────┘          └─────────┘          └─────────┘
```

## Notes

h1 runs tests/scripts/bgp_attr_inject_send.py. At session-up it
announces 10.48.1.0/24 with AS_PATH "65061". On the trigger file
/tmp/bgp_inbound_loop_withdraw.go it sends, in one write, 10.48.1.0/24
again with AS_PATH "65061 65060 65063" — z1's own AS in the path, as
when h1 has lost its route and now reaches the prefix through z1 — and
the control prefix 10.48.2.0/24 with "65061".

## Config Files

- z1.yaml: DUT — eBGP to h1 (passive) and to z2.
- z2.yaml: z1's downstream eBGP peer.

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Setup topology and establish sessions | |
| The neighbor's path reaches z1 and z2 | |
| The looped replacement withdraws the earlier path at z1 and downstream | |
| Teardown topology | |
