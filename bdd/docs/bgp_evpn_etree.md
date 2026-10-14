# EVPN E-Tree leaf ACs: roles in the data plane, Type-2 colouring (RFC 8317)

## Overview

As a network operator running an EVPN E-Tree
I want each leaf attachment circuit's role programmed into the cradle
data plane, so a leaf never reaches another leaf on the same PE, and a
MAC learned on a leaf AC advertised with the E-Tree community's
Leaf-Indication flag, so a receiving PE carries that flag into its own
data plane FDB.

`router bgp afi-safi evpn etree` exists only with `--feature etree`, and
a leaf AC needs the cradle data plane: the kernel bridge cannot keep
leaves apart, so a commit naming one without `system ebpf` (or
`system cradle`) is refused. zebra-rs's engine supervisor sends each
role (`SetEtreeRole`) before it attaches the port, and again to a
respawned engine before re-attaching its ports.

Known unicast from a leaf toward a flagged MAC on another PE is dropped
by that PE's engine before encapsulation; cradle-rs proves that drop
over a zebra-rs-driven VXLAN fabric. This feature stops at the flag
reaching z2's engine FDB.

```
```

## Config Files

- z1.yaml — EVPN/VXLAN, no `system ebpf` yet.
- z1-etree.yaml — z1 with the managed engine, its ports, and l1 and l2
  as leaf ACs.
- z2.yaml — a root-only PE with the managed engine.

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Setup topology and the EVPN session | |
| A leaf AC is refused without the cradle data plane | |
| With the engine on, the leaf roles are programmed and the ports attached | |
| A leaf reaches the root on its PE but not the other leaf | |
| Only the MACs learned on leaf ACs are advertised as leaves | |
| A respawned engine gets the roles back before the ports | |
| A leaf AC turned into a root reaches the other leaf and loses its colour | |
| Teardown topology | |
