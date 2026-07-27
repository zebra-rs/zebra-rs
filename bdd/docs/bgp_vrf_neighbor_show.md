# Per-VRF BGP neighbor config-echo in the neighbor detail show

## Overview

As an operator of an L3VPN PE
I want the per-VRF neighbor session and per-AFI knobs to be reflected in
`show bgp vrf <name> neighbor`
So that description, timers, update-source, ebgp-multihop, ttl-security,
add-path, and graceful-restart / long-lived-GR are staged and rendered
for a per-VRF CE neighbor exactly as for a global neighbor.

One scenario per knob, each asserting the neighbor detail renders the
configured value. CE1 carries the session + per-AFI knobs (established so
the negotiated capabilities show); CE2 carries ttl-security, which is
mutually exclusive with CE1's ebgp-multihop (echoed regardless of session
state).

## Test Topology

```
   ce1(65001) ─┐
               ├─ pe1 (65000, vrf-cust)
   ce2(65002) ─┘
```

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Build the config-echo VRF topology | |
| description is rendered | |
| hold-time is rendered | |
| idle-hold-time is rendered | |
| update-source is rendered as the local host | |
| ebgp-multihop is rendered | |
| add-path capability is rendered | |
| graceful-restart is negotiated with a restart time | |
| long-lived-graceful-restart is rendered | |
| ttl-security (GTSM) is rendered | |
| Teardown topology | |
