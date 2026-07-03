# Timer Configuration

The OSPF protocol timers are configured per interface, under the
area/interface entry. All defaults match RFC 2328 Appendix C
("Configurable Parameters").

```
router ospf {
  area 0.0.0.1 {
    interface enp0s7 {
      enable true;
      hello-interval 5;
      dead-interval 20;
    }
  }
}
```

| YANG leaf | Default | Range | Units |
|---|---|---|---|
| `/router/ospf/area/<id>/interface/<n>/hello-interval` | 10 | 1..65535 | seconds |
| `/router/ospf/area/<id>/interface/<n>/dead-interval` | 40 | 1..4294967295 | seconds |
| `/router/ospf/area/<id>/interface/<n>/retransmit-interval` | 5 | 1..65535 | seconds |

Notes:

- **`hello-interval`** and **`dead-interval`** must match on all
  routers on the same segment for adjacency to form. The on-the-wire
  Hello carries both; mismatches cause Hellos to be silently
  discarded and the adjacency never leaves `Down`. The conventional
  ratio is `dead = 4 × hello`; sub-second adjacency detection is
  better delegated to [BFD](ch-08-02-ospf-bfd.md).
- **`retransmit-interval`** governs how often unacknowledged LSAs in
  the per-neighbor `ls_rxmt` list are re-sent. The default of 5 s
  is conservative and rarely needs tuning on healthy links.
