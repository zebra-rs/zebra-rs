# EVPN Type-2 multihoming signals over SRv6 — ESI on the MAC route

## Overview

As a network operator multihoming a CE to two EVPN-over-SRv6 PEs
I want a MAC learned on an Ethernet Segment's access port to advertise
its Type-2 under the segment ESI (RFC 7432 §7.1), alongside both PEs'
per-ES Type-1 A-D and Type-4 routes, so a receiver holds the complete
input set for §8.4 aliasing and §8.2 mass withdraw.

Scope is the SIGNAL set, not its consumption: zebra-rs does not yet
alias MAC traffic across the segment's PEs nor mass-withdraw MACs on
a per-ES A-D loss (both exist for VPWS only — `vpws_gather_remotes`
gates on per-ES A-D liveness; the MAC install path does not). What is
proven here is that every route a consumer would need is originated,
exchanged and revoked correctly under `encapsulation srv6`.

The ES machinery itself (Type-4/ES-Import RT, membership, DF election)
is covered by bgp_evpn_es under the default encapsulation with no MACs;
single-PE runtime ESI bind/unbind by bgp_evpn_srv6_macip. This
feature is the two-PE composition: a segment shared by both PEs, bound
on z1 to an access port in the STARTUP config (the binding resolves via
the RibRx::LinkAdd replay — host0 is created only after the config
lands), and a CE MAC learned there. z2 configures the segment's ESI
but binds no port: its Type-4 and per-ES A-D need none, and a bound
port's own auto-generated MAC would originate an ESI-carrying Type-2
from z2 that never transitions, defeating whole-output assertions on
z1's bind/unbind. (Note z1's host0 own MAC is bridge-learned and
advertised too — every z1 Type-2 sheds the ESI together on unbind.)

```
```

## Config Files

- z1.yaml, z2.yaml — `advertise-all-vni` + `encapsulation srv6`, a
  locator each, the shared `ethernet-segment es1` (bound to `host0`
  on z1 only), and the EVPN AFI/SAFI as the only negotiated family.

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Setup topology and the EVPN session over SRv6 | |
| Both PEs discover each other on the segment under SRv6 encapsulation | |
| A MAC on one attached PE advertises under the segment ESI | |
| Unbinding the access port returns the MAC to single-homed | |
| Deleting the segment revokes the mass-withdraw signal set | |
| Teardown topology | |
