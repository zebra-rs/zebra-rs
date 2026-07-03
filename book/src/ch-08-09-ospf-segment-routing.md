# Segment Routing

OSPFv2 SR-MPLS (RFC 8665) is configured at instance and per-interface
scope:

```
router ospf {
  segment-routing mpls;
  area 0 {
    interface enp0s6 {
      enable true;
      prefix-sid {
        index 16001;
      }
    }
  }
}
```

| YANG leaf | Type | Notes |
|---|---|---|
| `/router/ospf/segment-routing` | enum `{ mpls }` | Enables Router Information LSA (RFC 7770) advertising SR capability. |
| `/router/ospf/area/<id>/interface/<n>/prefix-sid/index` | `uint32` | SID-index form (advertised as Extended Prefix LSA, RFC 7684). |
| `/router/ospf/area/<id>/interface/<n>/prefix-sid/absolute` | `uint32` | Absolute-label form (alternative to index). |

`index` and `absolute` are mutually exclusive — set one or the
other. Toggling `segment-routing mpls` originates or flushes the
Router Information LSA and all Extended Prefix LSAs for configured
interfaces in a single step.
