# Interface-to-bridge enslavement (`interface <if-name> bridge <bridge>`)

## Overview

As a network operator
I want `interface <if-name> bridge <bridge>` to enslave a port to a bridge
So that the binding is staged and applied once both the interface and the
bridge exist — config order is free (equivalent to
`ip link set <if-name> master <bridge>`).
The binding is durable desired-state, mirroring `interface <if-name> vrf
<vrf>`: it survives the bridge being created AFTER the interface config, an
explicit unbind clears it, and the bridge being deleted then re-created
re-applies it. We drive config with `apply command` (surgical set/delete)
and assert the kernel state via `ip -o link show <if>` — `show interface`
does not expose the master.
Topology: one namespace `z1` with a single `dummy` port `dum0`. The bridge
is created by the daemon from config (a namespace-internal kernel device),
so no host-side bridge/veth scoping is needed.

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Setup namespace with a dummy port | |
| A - binding set before the bridge exists is applied once it is created | |
| B - unbind clears the pending binding before the bridge appears | |
| C - binding survives the bridge being deleted and re-binds on re-create | |
| Teardown topology | |
