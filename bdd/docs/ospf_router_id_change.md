# OSPFv2 Router-ID set / change / delete on a live adjacency

## Overview

As a network operator
I want zebra-rs to react correctly when an OSPFv2 instance's Router-ID is
set, changed, or deleted while an adjacency is already up, so the peer
re-learns the new identity, the database advertised under the old identity
is withdrawn, and forwarding keeps working.
Two routers on a point-to-point link, each advertising a loopback that is
numerically distinct from any Router-ID, so a Router-ID only ever appears
in the database as an *advertising router* (never as a stub prefix). That
makes "the old Router-ID is gone" a clean, unambiguous assertion.

## Test Topology

```
    r1 --- 10.0.12.0/30 (point-to-point, area 0.0.0.0) --- r2
       eth1                                            eth2
    loopbacks: 192.168.11.1/32 (r1)        192.168.22.1/32 (r2)
    Router-IDs: r1 starts 1.1.1.1, r2 fixed 2.2.2.2
```

## Notes

The bugs this guards against:
* Every daemon boots with the constructor default Router-ID (10.0.0.1) and
  only adopts the configured value once config is applied. The LSA
  originated under the default was never withdrawn, so it lingered (and was
  even kept refreshed) as a phantom node — two routers booting as 10.0.0.1
  fought a sequence-number war and SPF failed to install transit routes,
  so even a fresh bring-up could leave loopbacks unreachable.
* OSPFv2 keys a neighbour by its source address and only recorded the
  peer's Router-ID at neighbour creation. A peer that changed its Router-ID
  kept its OLD Router-ID in our neighbour table forever — our Router-LSA
  pointed at a node that no longer originated one, and the peer's new
  identity never entered SPF.

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Setup point-to-point topology, reach Full and exchange loopbacks | |
| Changing r1's Router-ID re-forms the adjacency and withdraws the old identity | |
| Deleting r1's Router-ID is handled gracefully and keeps forwarding | |
| Setting an explicit Router-ID again re-converges the adjacency | |
| Teardown topology | |
