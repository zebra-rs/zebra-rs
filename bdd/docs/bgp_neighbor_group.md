# BGP neighbor-group inheritance end-to-end

## Overview

As a network operator
I want a peer that only references a neighbor-group (no per-peer remote-as)
to inherit the group's remote-as, establish a session, and react to
later changes to the group's remote-as.
This exercises the runtime path landed in PRs #758 (static-peer
resolver), #760 (reactive sweep on group remote-as Set/Delete), and
#762 (group-level delete cascade) through the full YAML/YANG/CLI
stack — not just the in-memory callback wiring covered by the
unit tests in #764.

## Test Topology

```
  ┌─────────────────────────────────────────┐
  │                   br0                   │
  └─────────────┬───────────────┬───────────┘
                │               │
           ┌────┴────┐     ┌────┴────┐
           │   z1    │     │   z2    │
           │ AS65001 │     │ AS65002 │
           │192.168. │     │192.168. │
           │  0.1/24 │     │  0.2/24 │
           └─────────┘     └─────────┘
```

## Config Files

- z1-1.yaml: AS 65001, neighbor-group "RR" with remote-as 65002,
- z1-2.yaml: same shape, but RR's remote-as is 65099 (wrong) —
- z2-1.yaml: plain AS 65002 peer to 192.168.0.1 remote-as 65001.

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Setup topology | |
| Inheritance — peer with only a neighbor-group reference establishes | |
| Reactive sweep — changing the group's remote-as drops the session | |
| Reactive sweep — restoring the group's remote-as brings it back | |
| Teardown topology | |
