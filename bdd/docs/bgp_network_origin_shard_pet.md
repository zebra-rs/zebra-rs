# BGP IPv4 network origination is advertised under shards + peer-task

## Overview

Repro for a reported bug: a speaker with the RIB sharded
(router bgp sharding rib-sharding 4) AND per-peer egress tasks (router bgp sharding peer-sharding true)
configured with IPv4 network statements never advertises those networks to
its neighbor.
Key fact: IPv4-unicast AFI/SAFI is enabled by DEFAULT on every neighbor,
even one whose transport address is IPv6 (it is only off when explicitly
set "afi-safi ipv4 enabled false"). So the iBGP neighbor below — peered over
an IPv6 transport with the ipv6 family also enabled — negotiates
IPv4-unicast too and MUST receive the originated IPv4 networks (IPv4 NLRI
with an IPv4 next-hop carried over the IPv6 session).
z1 is the device under test, configured exactly like the report: AS 65501,
shards 4 + peer-task true, originating 0.0.0.0/0 and 5.5.5.0/24, with one
iBGP neighbor z2 over IPv6.

## Test Topology

```
  z1 (AS65501)  ---- iBGP over IPv6 ----  z2 (AS65501)
  2001:db8::1/64                          2001:db8::8/64
  shards 4 + peer-task
  originates 0.0.0.0/0, 5.5.5.0/24
```

## Notes

Both on bridge br0.

## Test Scenarios

| Scenario | Result |
|----------|--------|
| the speaker and its iBGP neighbor establish over IPv6 | |
| z1 originates the IPv4 networks into its own Loc-RIB | |
| z2 receives the originated IPv4 networks (the reported bug) | |
| dropping a network statement withdraws it from the neighbor (route_del at N>1) | |
| Teardown topology | |
