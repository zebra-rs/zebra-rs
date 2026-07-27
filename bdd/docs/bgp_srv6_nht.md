# BGP route inherits SRv6 segments from its covering route

## Overview

As a network operator
I want a BGP route whose next-hop is reachable only through a
BGP-over-SRv6 transport route to resolve recursively through it and
inherit the H.Encap segment list — the BGP twin of the static-route
inheritance in @static_srv6_nht, and the SRv6 analog of Inter-AS
Option C (service routes riding a BGP-learned transport tunnel).

## Test Topology

```
  ┌────────┐ i1 ── i2 ┌────────┐ i1 ──────── i1 ┌────────┐ i2 ─────── i1 ┌────────┐
  │   z4   │──────────│   z1   │────────────────│   z2   │───────────────│   z3   │
  │ service│ 2001:db8:│ egress │2001:db8:12::/64│  core  │2001:db8:23::/64 ingress│
  │  node  │ cafe::/64│ LOC1   │                │        │               │        │
  └────────┘          └────────┘                └────────┘               └────────┘
   lo: 3001:db8:100::1     z2 knows ONLY the links and z1's locator
   (service prefix          fcbb:bbbb:1::/48 — service prefixes cross
    aggregate via BGP)      it exclusively inside SRv6 encapsulation
```

## Notes

- Transport: z1<->z3 iBGP with `encapsulation-type srv6`; z1
  redistributes connected, so 2001:db8:cafe::/64 (the z1-z4 subnet)
  arrives at z3 as an SRv6 service route carrying z1's End.DT6 SID
  fcbb:bbbb:1:40::.
- Service: z4<->z3 iBGP. The TCP session itself crosses the core
  inside the transport tunnel (encap at z3, decap at z1, plain
  delivery to z4). z4 redistributes its blackhole aggregate
  3001:db8:100::/64, which arrives at z3 with next-hop cafe::4 — an
  address covered ONLY by the SRv6 transport route. NHT resolves the
  next-hop through it and the installed route inherits the segment
  list: `proto bgp ... encap seg6 segs [fcbb:bbbb:1:40::]`.
- The ping to z4's loopback proves the end-to-end datapath: z2
  cannot route the service prefix, so only the inherited
  encapsulation can carry the traffic.

## Config Files

- z1.yaml, z2.yaml, z3.yaml, z4.yaml

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Setup topology and converge the SRv6 transport | |
| Service route resolves through the SRv6 transport and inherits its segments | |
| Teardown topology | |
