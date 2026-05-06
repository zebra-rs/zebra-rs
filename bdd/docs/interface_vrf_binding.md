# Interface VRF Binding

## Overview

As a network operator
I want to enslave individual interfaces to a VRF master device
So that traffic on those interfaces is routed in the VRF's table instead
of the default routing instance.

## Test Topology

```
              ┌─────────────────────┐
              │         z1          │
              │                     │
              │   ┌─────────────┐   │
              │   │  vrf vrf1   │   │   table-id (allocated)
              │   │  ifindex N  │   │
              │   └──────┬──────┘   │
              │          │ master   │
              │   ┌──────┴──────┐   │
              │   │   enp0s6    │   │   192.168.10.1/24
              │   └─────────────┘   │
              │                     │
              │       enp0s7        │   default VRF
              └─────────────────────┘
```

## Config Files

- z1.yaml:
  - `vrf vrf1`
  - `interface enp0s6 vrf vrf1`
  - `interface enp0s6 ipv4 address 192.168.10.1/24`
  - `interface enp0s7 ipv4 address 10.0.0.1/24` (default VRF, control)

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Configure VRF; verify `ip -d link show vrf1` reports `vrf table <id>` | |
| Configure interface VRF binding; verify `ip -d link show enp0s6` reports `master vrf1` | |
| `show vrf` lists vrf1 with enp0s6 in Members column | |
| `show interface brief` shows VRF column = `vrf1` for enp0s6, `default` for enp0s7 | |
| Configure IPv4 address before VRF binding (same commit); kernel ends up with the address in the VRF's table | |
| `delete interface enp0s6 vrf`; verify `ip -d link show enp0s6` reports `nomaster` | |
| Re-bind enp0s6 from vrf1 to a second `vrf vrf2`; verify `master vrf2` | |
| Configure binding before the kernel device exists; create the netdev (e.g. `ip link add type dummy`); binding fires automatically | |
| Configure binding before the VRF; commit creates VRF first then enslaves enp0s6 | |
| `delete vrf vrf1` while enp0s6 is bound; kernel detaches enp0s6 (`ip link show enp0s6` reports no master); operator's binding intent is retained so re-creating vrf1 re-enslaves | |
| Teardown: delete all VRFs and bindings; interfaces return to default VRF | |
