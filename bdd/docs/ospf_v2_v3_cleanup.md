# Deleting one OSPF version withdraws its routes and labels, not the other's

## Overview

OSPFv2 and OSPFv3 both install their routes and MPLS ILM entries in the
RIB as OSPF, v2 in IPv4 and v3 in IPv6. Deleting `router ospfv3` left
its routes behind for good: the RIB's cleanup had no rtype for
"ospfv3". Deleting `router ospf` withdrew every OSPF route and label,
OSPFv3's IPv6 ones too, and OSPFv3 never re-installed them.

r1 and r2 run both versions over one dual-stack point-to-point link,
both with SR-MPLS. r1's loopback 192.168.1.1/32 carries the OSPFv2
Prefix-SID index 11 (label 16011), its loopback 2001:db8::1/128 the
OSPFv3 Prefix-SID index 1 (label 16001); r2's own loopbacks carry
labels 16012 (v2) and 16002 (v3). r2 deletes one version at a time and
must keep the other's routes and labels.

## Config Files

- r1.yaml: OSPFv2 and OSPFv3 with SR-MPLS; loopback Prefix-SIDs 16011 (v2), 16001 (v3).
- r2.yaml: the same; loopback Prefix-SIDs 16012 (v2), 16002 (v3).

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Both versions install r1's loopbacks and Prefix-SIDs on r2 | |
| Deleting OSPFv3 withdraws its IPv6 routes and labels only | |
| OSPFv3 comes back | |
| Deleting OSPFv2 withdraws its IPv4 routes and labels only | |
| Teardown | |
