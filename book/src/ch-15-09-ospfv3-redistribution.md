# Route Redistribution

OSPFv3 redistribution originates **AS-External-LSAs** (LS type
`0x4005`, RFC 5340 §A.4.7) flooded AS-wide, with the same E1/E2
metric semantics and source list as OSPFv2 (see
[the v2 Route Redistribution page](ch-08-15-ospf-redistribution.md)
for the metric model):

| YANG leaf (`/router/ospfv3/redistribute/…`) | Type | Default |
|---|---|---|
| `connected` | presence container | — (absent = off) |
| `static` | presence container | — (absent = off) |
| `kernel` | presence container | — (absent = off) |
| `isis` | presence container | — (absent = off) |
| `bgp` | presence container | — (absent = off) |
| `<source>/metric` | uint32, 0..16777214 | 20 |
| `<source>/metric-type` | `type-1` \| `type-2` | `type-2` |

```
router ospfv3 {
  router-id 10.0.0.2;
  redistribute {
    connected {
      metric 20;
      metric-type type-2;
    }
    static;
  }
  area 0 {
    interface enp0s6 {
      enabled true;
    }
  }
}
```

Notes:

- `redistribute connected` matters mainly for interfaces *outside*
  OSPF — the prefixes of OSPF-enabled interfaces are already
  advertised through Intra-Area-Prefix-LSAs.
- `redistribute bgp` additionally serves the SRv6 L3VPN PE–CE
  "down" direction: a PE injects the VPNv6 routes it imported into
  a VRF into the CE-facing OSPFv3 instance. Per-VRF OSPFv3
  instances receive only their own VRF's routes.
- Inside an NSSA, the per-area `redistribute connected` knob
  originates area-scoped NSSA-LSAs (`0x2007`) instead, translated
  to AS-External at the NSSA ABR — see
  [Area Types: Stub and NSSA](ch-15-03-ospfv3-area-types.md).

## Default route origination

`default-information originate [always] [metric] [metric-type]`
advertises an AS-External default (`::/0`) with the same knobs and
semantics as [the v2 page](ch-08-15-ospf-redistribution.md): with
`always` unconditionally, without it only while a non-OSPF default
route exists in the RIB (tracked via the RIB default-route watch).
The metric defaults to 10, E2.

Receive-side handling installs AS-External routes with the standard
RFC 2328 §16.4 preference and metric arithmetic, including
inter-area ASBR resolution through Inter-Area-Router-LSAs (§16.4
step 5) when the ASBR sits in another area — see
[Multi-Area Routing and the ABR](ch-15-04-ospfv3-multi-area-abr.md).
As with v2, externals carrying a non-zero forwarding address are
skipped.
