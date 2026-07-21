# BGP IPv4 unicast carried in MP_REACH_NLRI with an IPv4 next-hop

## Overview

As a network operator
I want IPv4 unicast reachability encoded in an MP_REACH_NLRI attribute
(RFC 4760 §3, AFI=1/SAFI=1 with the next-hop inside the attribute) to be
treated identically to the traditional NLRI field, because RFC 4760
senders such as xk6-bgp encode it that way while zebra-rs, FRR and GoBGP
emit traditional NLRI — so only a scripted speaker can produce this shape.
Regression for the issue fixed by PR #2045: such UPDATEs were accepted
without error but had no effect — no Loc-RIB entry, no FIB install, no
re-advertisement, no log line. The scripted speaker also sends a decoy
NEXT_HOP attribute; per RFC 4760 the next-hop inside MP_REACH supersedes
it, which the next-hop assertions pin down.

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
192.168.30.99), holds the session with keepalives, and withdraws the
prefix through the traditional withdrawn-routes field when the trigger
file /tmp/bgp_mp_reach_ipv4_withdraw appears.

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Setup topology and establish sessions | |
| MP_REACH-encoded IPv4 unicast enters the Loc-RIB with the MP_REACH next-hop | |
| The MP_REACH-learned route is re-advertised to a traditional peer | |
| A traditional withdraw removes the MP_REACH-announced route | |
| Teardown topology | |
