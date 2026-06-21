# VXLAN-to-bridge enslavement (`vxlan <name> bridge <bridge>`)

## Overview

As a network operator
I want `vxlan <name> bridge <bridge>` to enslave a VXLAN device to a bridge
So that an EVPN-style bridge port is set up in one step, with the VXLAN
bridge-slave defaults applied automatically.
This reuses the same staged bridge-bind as `interface <name> bridge
<bridge>` (a VXLAN is an ordinary kernel link), so config order is free.
In addition, binding a VXLAN to a bridge must yield the defaults from the
iproute2 recipe:
- `addrgenmode none` is the VXLAN creation default.
- `neigh_suppress on` + `learning off` are applied by
We assert kernel state via `ip -d link show <vni>` (the `-d` detail view
exposes addrgenmode and the bridge_slave port options).

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Setup namespace with a VXLAN device | |
| A - binding applies master and the VXLAN bridge-slave defaults | |
| B - deferred bind applies the defaults once the bridge is created | |
| Teardown topology | |
