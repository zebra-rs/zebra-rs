# IS-IS and OSPF give their Adjacency-SIDs different labels

## Overview

IS-IS, OSPFv2 and OSPFv3 each allocate a dynamic Adjacency-SID label
for every adjacency from their SRLB, and all three read the same one: the
default SR block's, 15000..15999.
IS-IS used to allocate from a pool of its own, so on a router running
it beside OSPF its first adjacency got 15000 while an OSPF adjacency
held it too. The node has one MPLS label table, which forwards a label
one way only: one protocol's Adjacency-SID went the other's way. All
three now draw from the node's shared set of local labels.

r1 and r2 run all three protocols over one dual-stack point-to-point
link, with SR-MPLS: each router has one adjacency per protocol, so it
must hold three Adjacency-SID labels, 15000, 15001 and 15002.

## Config Files

- r1.yaml: IS-IS, OSPFv2 and OSPFv3 with SR-MPLS; loopback Prefix-SIDs 16021, 16011, 16001.
- r2.yaml: the same; loopback Prefix-SIDs 16022, 16012, 16002.

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Each router installs one Adjacency-SID label per protocol | |
| Teardown | |
