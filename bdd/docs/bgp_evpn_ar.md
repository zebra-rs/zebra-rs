# BGP EVPN Assisted Replication (RFC 9574) control plane

## Overview

As a network operator
I want zebra-rs to signal RFC 9574 Assisted Replication roles in the
Type-3 (Inclusive Multicast) IMET route and build the BUM flood list
accordingly, so that an AR-LEAF offloads BUM replication to an
AR-REPLICATOR while an RNVE keeps plain ingress replication.
Test Topology — three iBGP (AS 65001) EVPN speakers on a shared bridge,
each with a local VXLAN (VNI 10) so every node originates a Type-3 IMET:
```
┌──────────────────────────────────────────────────────────┐
│                            br0                            │
└─────────┬─────────────────┬─────────────────┬─────────────┘
```
Roles (router bgp afi-safi evpn assisted-replication):
- z1: role replicator, replicator-ip 192.168.0.101 (the AR-IP)
- z2: role leaf
- z3: role none (default RNVE); also requests whole-VTEP P-FL pruning
The flood list is observed via the kernel VXLAN FDB: the daemon programs
zero-MAC (00:00:00:00:00:00) rows, one `dst` per flood target. There is
no actual BUM forwarding here — the FDB *decisions* are the unit under
test, so the AR-IP need not be a reachable interface.

## Notes

Roles (router bgp afi-safi evpn assisted-replication):
- z1: role replicator, replicator-ip 192.168.0.101 (the AR-IP)
- z2: role leaf
- z3: role none (default RNVE); also requests whole-VTEP P-FL pruning
  (pruned-flood-list broadcast-multicast + unknown-unicast)
The flood list is observed via the kernel VXLAN FDB: the daemon programs
zero-MAC (00:00:00:00:00:00) rows, one `dst` per flood target. There is
no actual BUM forwarding here — the FDB *decisions* are the unit under
test, so the AR-IP need not be a reachable interface.

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Setup topology and establish the EVPN iBGP full mesh | |
| Type-3 IMET routes are exchanged across the EVPN mesh | |
| AR-LEAF collapses its BUM flood list to the replicator's AR-IP | |
| RNVE floods to every remote VTEP (plain ingress replication) | |
| A whole-VTEP Pruned-Flood-List request drops the node from peers' flood lists | |
| Selective AR — the AR-LEAF originates a Leaf A-D toward the replicator | |
| Teardown topology | |
