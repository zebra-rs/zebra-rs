# Per-VRF BGP neighbor authentication (TCP-MD5 password, TCP-AO key-chain)

## Overview

As an operator of an L3VPN PE
I want `router bgp vrf <name> neighbor <addr> {password | tcp-ao}` to
authenticate the per-VRF CE session
So that a matching key establishes and a wrong key is actually rejected
— proving the per-VRF neighbor keys the connect socket AND the VRF's own
listener, not that auth is silently ignored.

One matching + one mismatching CE per knob:

The matching cases exercise both auth directions (PE-initiated dial via
the VRF-bound connect socket AND CE-initiated dial via the VRF listener);
the mismatching cases are the regression guard that a bad key can't slip
through.

## Test Topology

```
   ce1  ce2   ce3  ce4
     \   |     |   /
        pe1 (65000, vrf-cust)
```

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Build the auth VRF topology | |
| A matching TCP-MD5 password establishes the CE session | |
| A mismatched TCP-MD5 password is rejected | |
| A matching TCP-AO key-chain establishes the CE session | |
| A mismatched TCP-AO key-string is rejected | |
| Teardown topology | |
