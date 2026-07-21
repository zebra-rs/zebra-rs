# BGP IPv4 unicast carried in MP_REACH_NLRI / MP_UNREACH_NLRI

## Overview

As a network operator
I want IPv4 unicast encoded in the RFC 4760 multiprotocol attributes
(AFI=1/SAFI=1 — reachability in MP_REACH_NLRI §3 with the next-hop inside
the attribute, withdrawals in MP_UNREACH_NLRI §4) to be treated
identically to the traditional NLRI and Withdrawn Routes fields, because
RFC 4760 senders such as xk6-bgp encode it that way while zebra-rs, FRR
and GoBGP use the traditional fields — so only a scripted speaker can
produce these shapes.
Both directions were broken, and both failure modes are covered here:
- MP_REACH (fixed by PR #2045): the UPDATE was accepted without error but
- MP_UNREACH: AFI=1/SAFI=1 had no arm in the parser at all, so the whole
The scripted speaker also sends a decoy NEXT_HOP attribute; per RFC 4760
the next-hop inside MP_REACH supersedes it, which the next-hop assertions
pin down.

## Test Topology

```
  ┌─────────────────────────────────────────────────────────┐
  │                          br0                            │
  └───────┬────────────────────┬────────────────────┬───────┘
     ┌────┴────┐          ┌────┴────┐          ┌────┴────┐
     │   h1    │          │   z1    │          │   z2    │
     │ scripted│          │  (DUT)  │          │ zebra-rs│
     │ RFC4760 │─eBGP────▶│ AS65030 │◀────eBGP─│ AS65032 │
     │ AS65031 │          │192.168. │          │192.168. │
     │ .30.2/24│          │ 30.1/24 │          │ 30.3/24 │
     └─────────┘          └─────────┘          └─────────┘
```

## Notes

h1 runs tests/scripts/bgp_mp_reach_send.py: it announces 10.99.0.0/24
inside MP_REACH_NLRI (next-hop 192.168.30.2, decoy NEXT_HOP attribute
192.168.30.99) and then acts on trigger files, each consumed when it
fires so re-touching re-triggers:
/tmp/bgp_mp_reach_ipv4.announce, .withdraw_traditional, .withdraw_mp.

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Setup topology and establish sessions | |
| MP_REACH-encoded IPv4 unicast enters the Loc-RIB with the MP_REACH next-hop | |
| The MP_REACH-learned route is re-advertised to a traditional peer | |
| An MP_UNREACH withdraw removes the route without resetting the session | |
| A traditional withdraw also removes the MP_REACH-announced route | |
| Teardown topology | |
