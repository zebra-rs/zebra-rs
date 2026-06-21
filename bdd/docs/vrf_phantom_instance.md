# A top-level VRF must not spawn a phantom per-protocol instance

## Overview

Configuring a top-level `vrf <name>` creates the kernel VRF master, but
it is NOT a protocol per-VRF block — IS-IS and OSPF only own
`/router/<proto>/vrf/<name>/…`. Because the config manager broadcasts
every committed line to every protocol task, a too-greedy `vrf <name>`
match used to make IS-IS/OSPF spawn a phantom per-VRF instance for a VRF
that has no `router <proto> vrf` configuration. With the proto-anchored
`vrf_config_split` they must not.
This router has a top-level `vrf cust` plus IS-IS and OSPFv2 in the
default VRF only. `show task` lists each running protocol and its VRF;
it must show `isis` / `ospf` under `default` and never a `cust` row.
```
```

## Test Scenarios

| Scenario | Result |
|----------|--------|
| A bare top-level VRF spawns no per-VRF IS-IS / OSPF instance | |
| Teardown topology | |
