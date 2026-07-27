# BGP EVPN IGMP/MLD Join/Leave Synch routes (RFC 9251 Type 7/8)

## Overview

As a network operator
I want zebra-rs to originate, store, and route-reflect the RFC 9251
multihoming synch routes — Type 7 (IGMP/MLD Join Synch) and Type 8
(IGMP/MLD Leave Synch) — carrying their ES-Import RT and EVI-RT
extended communities, so the control-plane foundation for all-active
multihoming is exercised end to end. (DF election and the kernel-MDB
synch dataplane are still deferred — there is no organic ES-snoop
trigger yet, so origination is driven by the `clear bgp debug
igmp-*-sync-*` test command.)
Test Topology — two iBGP (AS 65001) EVPN speakers on a shared transport
bridge br0:
```
┌─────────────────────────────────┐
│               br0               │
└───────┬─────────────────┬───────┘
```
z2 originates a Type-7/8 synch route via
`clear bgp debug igmp-{join,leave}-sync-{originate,withdraw} <spec>`
(spec = `vni,esi,group[,source]`); z1 imports it into its EVPN RIB and
renders it under `show bgp evpn`, with the ES-Import RT and EVI-RT
extended communities preserved.

## Notes

z2 originates a Type-7/8 synch route via
`clear bgp debug igmp-{join,leave}-sync-{originate,withdraw} <spec>`
(spec = `vni,esi,group[,source]`); z1 imports it into its EVPN RIB and
renders it under `show bgp evpn`, with the ES-Import RT and EVI-RT
extended communities preserved.

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Setup topology and EVPN iBGP | |
| z2 originates a (*,G) Type-7 Join Synch route that z1 imports | |
| Withdrawing the Type-7 route removes it from z1 | |
| z2 originates a source-specific (S,G) Type-8 Leave Synch route | |
| Withdrawing the Type-8 route removes it from z1 | |
| Teardown topology | |
