# BGP IPv4-unicast resumable session-up sync cursor (Tier 1a)

## Overview

Exercises the ZEBRA_BGP_SYNC_CHUNK resumable cursor: the device under
test z2 runs with sync chunk 1, so its session-up IPv4-unicast dump to
a late peer runs one prefix per main-loop tick instead of one
uninterruptible pass. Pins that the chunked dump still delivers every
route, sends EoR, registers each route in adj_out (so a later withdraw
+ peer-down reach the synced peer), and matches the legacy one-shot
result.

## Test Topology

```
  z1 (AS65001) ── z2 (AS65002, sync chunk 1) ── z3 (AS65003)  late peer → cursor sync
   origin          device under test            recv
```

## Notes

z1 originates 10.1.0.0/24, 10.2.0.0/24, 10.3.0.0/24. All on bridge br0.

## Test Scenarios

| Scenario | Result |
|----------|--------|
| z1 and the cursor device z2 come up; z2 holds the routes | |
| the late peer z3 gets every route via the chunked cursor | |
| z1 withdraws one route; the withdraw reaches the cursor-synced peer z3 | |
| z1's session drops; the peer-down sweep clears its routes from z3 | |
| Teardown topology | |
