# OSPFv2 and OSPFv3 give their Adjacency-SIDs different labels

## Overview

OSPFv2 and OSPFv3 each allocate a dynamic Adjacency-SID label for every
Full adjacency from the same SRLB, 15000 and up. Each used to allocate
from its own pool, so a router running both gave its first v2 and its
first v3 adjacency the same label, 15000. The node has one MPLS label
table, and the ILM kept one OSPF entry per label: one version's
Adjacency-SID did not forward. The two now draw from the node's shared
set of local labels.

r1 and r2 run both versions over one dual-stack point-to-point link,
both with SR-MPLS: each router has one v2 and one v3 adjacency, so it
must hold two Adjacency-SID labels, 15000 and 15001.

## Config Files

- r1.yaml: OSPFv2 and OSPFv3 with SR-MPLS; loopback Prefix-SIDs 16011 (v2), 16001 (v3).
- r2.yaml: the same; loopback Prefix-SIDs 16012 (v2), 16002 (v3).

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Each router installs one Adjacency-SID label per OSPF version | |
| Teardown | |
