# PIMv6 two-router neighborship forms over link-local transport

## Overview

As a network operator
I want two zebra-rs routers to run PIMv6 on an IPv6 link and discover
each other through link-local-sourced Hellos, so the PIMv6 transport
(raw protocol 103 over IPv6, ff02::d joins, in6_pktinfo source
pinning and the pseudo-header checksum) and the address-family split
(`router pim ipv6` spawning a default-table Pim<Ipv6>) are exercised
router-to-router.

PIMv6 Hellos are sourced from the interface link-local (fe80::/10,
RFC 7761 §4.3.1), so each router learns the peer as a link-local
neighbor.

## Test Topology

```
    p1 (2001:db8:12::1/64, fe80 auto) --- veth --- p2 (2001:db8:12::2/64, fe80 auto)
       eth1                                           eth2
```

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Two PIMv6 routers discover each other over link-local | |
| Teardown topology | |
