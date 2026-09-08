# A route reflector reflects a client's route to non-client iBGP peers (IPv6)

## Overview

As a network operator
I want RFC 4456 §6 reflection in full: a route learned from a client
goes to every other client AND to every non-client iBGP peer, while a
route learned from a non-client goes to clients only
So that the standard hierarchical design — reflectors that peer with
each other as ordinary iBGP neighbors, each serving its own clients —
actually carries every client's routes across the reflector tier.

The IPv6 twin of bgp_rr_client_to_nonclient: the reflection gate is
written per family in zebra-rs, so the rule has to be pinned per family.

RFC 4456 §6, on receiving a route from an iBGP peer:
- from a Non-Client: reflect to all the Clients;
- from a Client: reflect to all the Non-Client peers and also to the
Both reflected forms carry ORIGINATOR_ID (the originator's BGP
Identifier) and CLUSTER_LIST (the reflector's cluster id prepended).

zebra-rs kept no record of whether a path came from a client, and
every egress builder gated iBGP-to-iBGP forwarding on the DESTINATION
being a client alone — so the second bullet's "Non-Client peers" half
never happened: a client's route reached the other clients and stopped
at the reflector. Every reflector BDD until now made every iBGP
neighbor a client, which is why it went unnoticed.

## Test Topology

```
  ┌───────────────────────────────────────────────────────────────────┐
  │                               br0                                 │
  └────┬──────────────┬──────────────┬──────────────┬──────────────┬──┘
   ┌───┴───┐      ┌───┴───┐      ┌───┴───┐      ┌───┴───┐      ┌───┴───┐
   │  z2   │      │  z3   │      │  z1   │      │  z4   │      │  z5   │
   │client │      │client │      │  RR   │      │non-cl.│      │non-cl.│
   │ id .2 │      │ id .3 │      │ id .1 │      │ id .4 │      │ id .5 │
   └───────┘      └───────┘      └───────┘      └───────┘      └───────┘
```

## Notes

Router-ids are 10.50.0.N; session addresses are 2001:db8:50::N.

- z2 (client) originates 2001:db8:20::/64; z3 is a client that only listens.
- z4 (non-client) originates 2001:db8:40::/64; z5 is a non-client that only listens.

## Config Files

- z1.yaml: reflector — z2, z3 route-reflector clients; z4, z5 plain iBGP.
- z2.yaml / z2-withdrawn.yaml: client, with and without its network.
- z3.yaml, z5.yaml: listeners. z4.yaml: non-client originator.

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Setup topology and establish all four sessions | |
| Client to client — the other client receives the reflected route (control) | |
| Non-client to client — the clients receive the reflected route (control) | |
| Client to non-client — every non-client iBGP peer receives the client's route | |
| Non-client to non-client — a non-client's route is NOT reflected to another non-client (control) | |
| Withdrawing the client's route removes it from the non-clients too | |
| Teardown topology | |
