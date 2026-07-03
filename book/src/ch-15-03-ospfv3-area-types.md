# Area Types: Stub and NSSA

OSPFv3 supports the same area-type model as OSPFv2 — `normal`
(default), `stub`, and `nssa` — with a configuration surface that is
schema-identical to the v2 one; only the top-level keyword differs.
The semantics (which external information enters the area, the
E-bit/N-bit option negotiation that rejects mismatched Hellos, the
NSSA translator election) are shared with v2 and described in detail
in the OSPFv2 chapter's
[Area Types page](ch-08-13-ospf-area-types.md); this page covers the
v3 specifics.

| YANG leaf (`/router/ospfv3/area/<id>/…`) | Default | Values |
|---|---|---|
| `area-type` | `normal` | `normal` \| `stub` \| `nssa` |
| `no-summary` | `false` | boolean — totally-stubby / totally-NSSA |
| `nssa-default-originate` | `false` | boolean — ABR originates a default Type-7 |
| `nssa-suppress-fa` | `false` | boolean — zero the forwarding address on translation |
| `nssa-translator-role` | `candidate` | `candidate` \| `always` \| `never` |
| `redistribute/connected/metric` | 20 | 0..16777214 |
| `redistribute/connected/metric-type` | `type-2` | `type-1` \| `type-2` |

In place of OSPFv2's Type-7, OSPFv3 NSSA externals ride the
**NSSA-LSA** (function code 7, LS type `0x2007`, RFC 5340 §A.4.9),
which shares the AS-External-LSA body; `show ospfv3 database` lists
them as `NSSA-LSA`. Translation at the NSSA ABR produces
AS-External-LSAs (`0x4005`) flooded to the rest of the domain.

The ABR of an NSSA, originating a default into the area:

```
router ospfv3 {
  area 0 {
    interface enp0s6 {
      enable true;
    }
  }
  area 0.0.0.1 {
    area-type nssa;
    nssa-default-originate true;
    interface enp0s7 {
      enable true;
    }
  }
}
```

The internal ASBR, redistributing its connected IPv6 prefixes into
the NSSA as NSSA-LSAs (the redistribute knob is per-area because
NSSA-LSAs are area-scoped):

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
    interface enp0s8 {
      enable true;
    }
  }
}
```

Internal routers see the redistributed prefix and the default
(`::/0`) in `show ospfv3 route`; backbone routers see the translated
AS-External-LSA and install the prefix — the observable proof that
translation ran. `nssa-translator-role never` on the (sole) ABR
keeps the prefix inside the area. Base NSSA translation and the
translator roles are BDD-validated for v3
(`ospfv3_nssa.feature`).

One v3-specific note on Link-State IDs: OSPFv3 NSSA/AS-External
LSAs do not encode the prefix in the LS-ID the way v2 does; zebra-rs
derives the v3 LS-ID from a hash of the full prefix so that
different prefixes sharing high-order bits cannot collide.
