# BGP per-VRF show command

## Overview

As a network operator
I want to inspect the per-VRF state of a running zebra-rs
Using a single-namespace topology that drives the local config
callbacks end-to-end so `show bgp vrf` reports the committed
Route Distinguisher / MPLS label / task state, and the named forms
redirect into the spawned per-VRF task.

## Test Topology

```
  ┌─────────┐
  │   z1    │   AS 65001
  │ 192.168 │   vrf-blue: RD 65001:100, RT 65001:100
  │  .0.1/24│
  └─────────┘
```

## Config Files

- z1-1.yaml: baseline `router bgp` with no per-VRF block.
- z1-2.yaml: adds top-level vrf-blue (with RT import/export) and

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Setup topology | |
| Configure vrf-blue and observe via show | |
| Inspect vrf-blue via the `show bgp vrf` tree | |
| Remove the BGP VRF block and observe the RD clear | |
| Teardown topology | |
