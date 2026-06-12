# BGP table-map for IPv6 unicast gates RIB installs per address family

## Overview

As a network operator
I want `router bgp afi-safi ipv6 table-map <policy>` to filter and
rewrite IPv6 best paths at the kernel-install boundary — with the
same semantics as the IPv4 table-map, and strictly scoped to its
own address family: a v6 binding must never touch v4 installs.
The exercise: a single v4 BGP session carries both families
(ipv4 + ipv6 afi-safi). z1 advertises three v6 prefixes and one v4
prefix. z2 binds table-map TMAP6 under `afi-safi ipv6` only:
entry 10 denies 2001:db8:100::/48, entry 20 permits
2001:db8:200::/48 with `set med 50`, entry 30 permits the rest.
All three v6 prefixes stay visible in `show bgp ipv6` throughout;
only the kernel routes move — and the v4 route installs untouched.

## Test Topology

```
  ┌─────────────────┐  192.168.0.0/30   ┌─────────────────┐
  │       z1        │  2001:db8:12::/64 │       z2        │
  │     AS65001     ├───────────────────┤     AS65002     │
  │ .1 / 12::1      │                   │ .2 / 12::2      │
  └─────────────────┘                   └─────────────────┘
```

## Config Files

- z1.yaml: AS 65001, networks 2001:db8:100::/48 + 2001:db8:200::/48
- z2.yaml: prefix-set DENY6 = { 2001:db8:100::/48 },
- z2-deny-more.yaml: DENY6 = { 2001:db8:100::/48,

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Setup topology and verify v6 install filter, MED rewrite, and v4 isolation | |
| Editing the referenced policy resyncs the v6 FIB without a session reset | |
| Deleting the v6 table-map restores unfiltered v6 installs | |
| Teardown topology | |
