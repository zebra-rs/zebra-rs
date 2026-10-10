# A configured OSPF Adjacency-SID takes its label from a dynamic holder

## Overview

As a network operator
I want an absolute Adjacency-SID I configure to get the SRLB label I
chose even when another protocol's dynamic Adjacency-SID holds it, so
that the label I pick does not succeed or fail by the order in which
adjacencies came up (docs/design/mpls-label-allocation.md §5.1).

IS-IS, OSPFv2 and OSPFv3 draw their dynamic Adjacency-SIDs from one
SRLB, 15000..15999, lowest label first. r1 starts with IS-IS only, so
its IS-IS adjacency holds 15000. Then OSPFv2 comes up with
`adjacency-sid absolute 15000` on the same link: IS-IS is told to let
15000 go, takes another label, and once its forwarding entry at 15000
is withdrawn, OSPFv2 advertises and installs 15000. In `show mpls ilm`
an IS-IS entry reads `i 115` and an OSPF one `O 110`.

## Test Topology

```
   r1 ──────────── r2
     10.0.12.0/30
   lo 192.168.1.1/2
```

## Test Scenarios

| Scenario | Result |
|----------|--------|
| IS-IS's adjacency holds the first SRLB label | |
| OSPFv2's configured Adjacency-SID moves IS-IS off 15000 | |
| Dropping the configuration gives 15000 back | |
| Teardown | |
