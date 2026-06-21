# BGP EVPN BUM segmentation — DF-gated gateway re-flood (RFC 9572 §5.3.1, Phase 6.2)

## Overview

As a network operator
I want only the elected Designated Forwarder among the gateways bordering a
region to deliver BUM into it, so that with multiple redundant gateways no
duplicate BUM is produced — the standby gateway drops the region from its
re-flood set.
Control-plane only (the eBPF replication is a follow-up). Two gateways z2 and
z4 border both region A (z1) and region B (z3); z2 (lower address) wins the
modulus DF election for both regions, so z2 re-floods and z4 stays standby.
```
┌──────────────────────────────────────────────────────────┐
│                            br0                            │
└────┬────────────┬────────────┬────────────┬───────────────┘
```

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Setup topology and establish the EVPN sessions | |
| The DF gateway owns both regions and re-floods across the boundary | |
| The standby gateway re-floods nothing (no duplicate BUM) | |
| Teardown topology | |
