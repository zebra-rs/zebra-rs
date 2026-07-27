# Per-VRF BGP neighbor per-AFI policy and prefix-set filters

## Overview

As an operator of an L3VPN PE
I want `router bgp vrf <name> neighbor <addr> afi-safi ipv4
{policy|prefix-set} {in|out}` to filter CE routes
So that inbound and outbound route policy works on a per-VRF CE
neighbor exactly as it does on a global neighbor — through the
per-VRF policy-actor plumbing (`bgp-vrf:<name>` proto,
`peer_policy_ident`), not just at the global scope.
One scenario per binding. CE1 advertises 10.0.1.1..5/32 into vrf-cust.
PE1's inbound filters on the CE1 neighbor drop .2 (prefix-set-in, a
permit-list omitting it) and .3 (policy-in). PE1 re-advertises the VRF
Loc-RIB to CE2, where the outbound filters on the CE2 neighbor drop .4
(prefix-set-out) and .5 (policy-out). .1 survives every filter and is
the control.

## Test Topology

```
   ce1 ────────── pe1 ────────── ce2
   AS 65001    AS 65000        AS 65002
   nets .1..5   vrf-cust        receiver
        .2 ── .1        .1 ── .2
       10.1.0.0/30    10.2.0.0/30
```

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Build the per-AFI policy VRF topology | |
| prefix-set in drops a CE prefix before the VRF Loc-RIB | |
| policy in denies a CE prefix into the VRF Loc-RIB | |
| prefix-set out withholds a VRF route from a CE neighbor | |
| policy out withholds a VRF route from a CE neighbor | |
| Teardown topology | |
