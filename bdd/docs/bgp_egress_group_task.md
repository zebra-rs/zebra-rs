# BGP per-update-group egress task (migration Phases 0-3)

## Overview

Per-update-group egress-task migration
(docs/design/bgp-egress-group-task-migration.md). At
ZEBRA_BGP_EGRESS_GROUP_TASK=1 the v4-unicast egress runs in one task per
update group (M tasks, not N peers): the task owns the group adj_out,
encodes each best path once, and fans the bytes to its member peers,
excluding the path's source (split-horizon).
This feature exercises the gate-on egress matrix through the group task:
z3 and z4 share one update group (same eBGP egress identity; remote-AS is
not part of the signature). z2 is the device under test, started with the
egress group task.

## Test Topology

```
                        ┌── z3 (AS65003)  early peer
  z1 (AS65001) ── z2 (AS65002) ──┤
                  egress group   └── z4 (AS65004)  late peer (Phase 3)
                  task (gate-on)
```

## Notes

All four on bridge br0. z1 originates 10.10.10.0/24 + 10.10.11.0/24.

## Test Scenarios

| Scenario | Result |
|----------|--------|
| a group forming spawns its egress task; early speakers establish | |
| routes propagate through the group task (Phase 1b event-driven advertise) | |
| advertised-routes reads the group adj_out, split-horizon filtered (Phase 5) | |
| a late peer z4 gets the routes on session-up sync (Phase 3) | |
| a clear soft-out re-fans the group through the task (Phase 4) | |
| z2's `show bgp ipv4 summary` PfxSnt comes from the group task (N=1, group gate only) | |
| an event-driven withdraw reaches BOTH the early and the late member (Phase 3 coherence) | |
| peer-down withdraws through the group task to both members (Phase 2/3) | |
| Teardown topology | |
