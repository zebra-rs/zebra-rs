# Multi-Area Topologies and the ABR

OSPFv3 supports multi-area configurations at the adjacency and
intra-area level. As in OSPFv2, an area is declared by listing
interfaces under it, and a router with enabled interfaces in two or
more areas is an Area Border Router:

```
router ospfv3 {
  router-id 10.0.0.1;
  area 0 {
    interface lo {
      enable true;
    }
    interface enp0s6 {
      enable true;
      network-type point-to-point;
    }
  }
  area 0.0.0.1 {
    interface enp0s7 {
      enable true;
      network-type point-to-point;
    }
  }
}
```

The instance originates **one Router-LSA per attached area**
containing only that area's links (RFC 5340 §3.4.3), so non-backbone
areas form adjacencies, flood, and run SPF exactly like the
backbone. NSSA machinery (redistribution, translation) is fully
per-area.

## Current limitation: no ABR summary origination

Unlike OSPFv2, the OSPFv3 ABR does **not yet originate**
Inter-Area-Prefix-LSAs (`0x2003`, the v3 Type-3 equivalent) or
Inter-Area-Router-LSAs (`0x2004`, the Type-4 equivalent). Received
inter-area LSAs are flooded, stored, and displayed
(`show ospfv3 database` lists them), but a zebra-rs v3 ABR does not
generate them from its routing table — so **inter-area reachability
through a zebra-rs OSPFv3 ABR does not work today**. This is the
most significant OSPFv2/OSPFv3 feature gap; see
[Gaps Relative to FRR ospf6d](ch-15-15-ospfv3-frr-gaps.md).

Until it lands, multi-area OSPFv3 deployments with zebra-rs are
limited to topologies where inter-area routing is not required of
the zebra-rs ABR (e.g. NSSA translation at the area edge, which
works — translated AS-External-LSAs are AS-scoped and don't need
Inter-Area-Prefix origination), or where another vendor's ABR does
the summarization. For the v2 behavior this chapter mirrors, see
[Multi-Area Routing and the ABR](ch-08-14-ospf-multi-area-abr.md).
