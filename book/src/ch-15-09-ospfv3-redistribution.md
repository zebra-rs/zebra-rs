# Route Redistribution

OSPFv3 redistribution originates **AS-External-LSAs** (LS type
`0x4005`, RFC 5340 §A.4.7) flooded AS-wide, with the same E1/E2
metric semantics as OSPFv2 (see
[the v2 Route Redistribution page](ch-08-15-ospf-redistribution.md)
for the metric model). The v3 source list differs from v2:

| YANG leaf (`/router/ospfv3/redistribute/…`) | Type | Default |
|---|---|---|
| `bgp` | presence container | — (absent = off) |
| `bgp/metric` | uint32, 0..16777214 | 20 |
| `bgp/metric-type` | `type-1` \| `type-2` | `type-2` |

- **Instance-level `redistribute bgp`** is the primary knob. Its
  main role is the SRv6 L3VPN PE–CE "down" direction: a PE injects
  the VPNv6 routes it imported into a VRF into the CE-facing OSPFv3
  instance. Per-VRF OSPFv3 instances receive only their own VRF's
  BGP routes.
- **There is no instance-level `redistribute connected` for v3**
  (v2 has one). Connected-prefix redistribution exists only
  per-NSSA-area:

```
router ospfv3 {
  area 0.0.0.1 {
    area-type nssa;
    redistribute {
      connected {
        metric 20;
        metric-type type-2;
      }
    }
    interface lo {
      enable true;
    }
  }
}
```

which originates area-scoped NSSA-LSAs (`0x2007`) translated to
AS-External at the NSSA ABR — see
[Area Types: Stub and NSSA](ch-15-03-ospfv3-area-types.md).

In practice this asymmetry is mild: OSPFv3 already advertises the
IPv6 prefixes of every OSPF-enabled interface through
Intra-Area-Prefix-LSAs (including loopbacks declared under an
area), so instance-wide connected redistribution matters mainly for
non-OSPF interfaces — a gap noted in
[Gaps Relative to FRR ospf6d](ch-15-15-ospfv3-frr-gaps.md).

Receive-side handling installs AS-External routes with the standard
RFC 2328 §16.4 preference and metric arithmetic; as with v2,
externals carrying a non-zero forwarding address are skipped, and
inter-area ASBR resolution (Inter-Area-Router-LSA fallback) is not
yet implemented for v3 — a backbone observer must share an area
with the ASBR or translator.
