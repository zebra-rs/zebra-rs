# A gateway address on two interfaces is two nexthops

## Overview

The RIB shares one nexthop group between routes with the same gateway.
It keyed the group on the address alone, so a route whose gateway was
already in use on another interface joined that group and left by the
other interface. An address names a neighbor only on its own link:
link-locals repeat across links, and OSPF hands over each attached route
as 0.0.0.0 on its interface. The group is now keyed on the interface the
route's source named as well.

## Test Topology

```
               z1 (lo 10.0.0.1, 2001:db8::1)
       z1-z2 /     \ z1-z3
            /       \
   fe80::1 z2       z3 fe80::1      both neighbors use fe80::1 toward z1
            \       /
 2001:db8:24::/64  2001:db8:34::/64
              \   /
               z4
```

## Config Files

- z1.yaml .. z4.yaml: loopbacks, IPv4 link addresses, the two IPv6
  link prefixes behind z2 and z3, OSPFv2 and OSPFv3 (SR-MPLS on the
  loopbacks only).

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Build the diamond with fe80::1 on both of z1's neighbors | |
| The route through z2 leaves by z1-z2 | |
| The route through z3 leaves by z1-z3 | |
| OSPF's attached routes name their own interfaces | |
| Teardown topology | |
