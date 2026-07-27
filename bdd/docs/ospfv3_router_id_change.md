# OSPFv3 Router-ID change on a live adjacency

## Overview

As a network operator
I want zebra-rs to withdraw the LSAs advertised under an OSPFv3 instance's
old Router-ID when that Router-ID changes on a running adjacency, so a
stale identity does not linger in every router's database until MaxAge.
Two OSPFv3 routers on a point-to-point link. OSPFv3 keys a neighbour by
Router-ID (RFC 5340 §10), so when o1's Router-ID changes o2 naturally
forms a fresh neighbour and the old one ages out on its dead timer. The
part that needs a fix is the database: the LSAs o1 originated under the
old Router-ID would otherwise survive as a phantom node. A Router-ID is
numerically distinct from any IPv6 prefix here, so "the old Router-ID is
gone from the database" is an unambiguous assertion.

## Test Topology

```
    o1 --- 2001:db8:12::/64 (point-to-point, area 0.0.0.0) --- o2
       eth1                                                eth2
    loopbacks: 2001:db8::1/128 (o1)            2001:db8::2/128 (o2)
    Router-IDs: o1 starts 1.1.1.1, o2 fixed 2.2.2.2
```

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Setup point-to-point topology and reach Full | |
| Changing o1's Router-ID re-forms the adjacency and withdraws the old identity | |
| Teardown topology | |
