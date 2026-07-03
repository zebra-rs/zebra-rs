# Timer Configuration

OSPFv3 protocol timers are configured per interface, under the
area/interface entry, with the same defaults as OSPFv2 (the two
versions share the OSPF core's timer constants).

```
router ospfv3 {
  area 0 {
    interface enp0s6 {
      enable true;
      hello-interval 5;
      dead-interval 20;
    }
  }
}
```

| YANG leaf (`/router/ospfv3/area/<id>/interface/<n>/…`) | Default | Type | Units |
|---|---|---|---|
| `hello-interval` | 10 | uint16 | seconds |
| `dead-interval` | 40 | uint32 | seconds |
| `retransmit-interval` | 5 | uint16 | seconds |

As in v2, `hello-interval` and `dead-interval` must match on all
routers of a link for the adjacency to form — mismatched Hellos are
silently discarded — and the conventional ratio is
`dead = 4 × hello`. Sub-second failure detection is better
delegated to [BFD](ch-15-17-ospfv3-bfd.md), whose v3 sessions run
over the IPv6 link-local addresses. `retransmit-interval` governs
re-sending of unacknowledged LSAs from the per-neighbor
retransmission list.
