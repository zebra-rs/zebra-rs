# BGP EVPN BUM segmentation — gateway re-flood primitive (RFC 9572 §6, Phase 6 control plane)

## Overview

As a network operator
I want a segmentation gateway to partition its learned VTEPs by region and
compute the split-horizon re-flood set per region — the control-plane
primitive the (eBPF) BUM-replication dataplane consumes — so that BUM
ingressing from one region is replicated only to VTEPs in the other regions,
never back into the region it came from.
This is the control-plane foundation for the Phase 6 eBPF gateway dataplane;
no packet forwarding happens yet (the replication offload is a follow-up).
Test Topology — region A (AS 65001) PE z1 and region B (AS 65002) PE z3 each
own a VXLAN (VNI 10); the gateway z2 borders both and learns one VTEP per
region.
```
┌──────────────────────────────────────────────────────────┐
│                            br0                            │
└─────────┬─────────────────┬─────────────────┬─────────────┘
```

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Setup topology and establish the EVPN sessions | |
| The gateway computes a split-horizon re-flood set per region | |
| The gateway is the elected DF and forwards | |
| Per-PE IMET is not propagated across the boundary (still segmented) | |
| Teardown topology | |
