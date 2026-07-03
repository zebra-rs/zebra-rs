# Route Redistribution

Instance-level `redistribute` injects routes from other sources into
OSPF as Type-5 AS-External LSAs (RFC 2328 §12.4.5), flooded AS-wide
into all normal areas. Configuring any redistribute source makes the
router an ASBR: the E-flag is set in its Router-LSAs so the rest of
the domain computes paths to it.

```
router ospf {
  router-id 10.0.0.2;
  redistribute {
    connected {
      metric 20;
      metric-type type-2;
    }
  }
  area 0 {
    interface lo {
      enable true;
    }
    interface enp0s6 {
      enable true;
      network-type point-to-point;
    }
  }
}
```

| YANG leaf (`/router/ospf/redistribute/…`) | Type | Default |
|---|---|---|
| `connected` | presence container | — (absent = off) |
| `bgp` | presence container | — (absent = off) |
| `<source>/metric` | uint32, 0..16777214 | 20 |
| `<source>/metric-type` | `type-1` \| `type-2` | `type-2` |

`connected` and `bgp` are the two supported sources today; each is a
presence container — naming it enables redistribution of that
source, deleting it flushes the corresponding Type-5s. Both knobs
also exist per VRF instance, where the subscription is scoped so a
VRF's OSPF sees only that VRF's routes.

## E1 vs E2 metrics

`metric-type` selects how the external metric combines with
internal cost (RFC 2328 §16.4):

- **`type-2`** (E2, the default): the route costs the LSA metric
  alone, everywhere. With `metric 20`, every router in the domain
  installs the external prefix at `[20]` regardless of its distance
  from the ASBR. E2 routes are always less preferred than any
  internal route.
- **`type-1`** (E1): the SPF cost to the ASBR is added to the LSA
  metric, so the total grows with distance — a router adjacent to
  the ASBR sees `[30]` (10 + 20) while a router two areas away sees
  `[40]`. Cross-area E1 computation relies on the ABR's Type-4
  ASBR-Summary; see
  [Multi-Area Routing and the ABR](ch-08-14-ospf-multi-area-abr.md).

## Forwarding address

zebra-rs always originates Type-5 LSAs with forwarding address
0.0.0.0, meaning traffic flows via the ASBR itself. On receipt,
LSAs carrying a non-zero forwarding address are currently skipped —
resolving the FA against an intra-area route (RFC 2328 §16.4
step 3) is not yet implemented.

## Redistribution into NSSA areas

Stub and NSSA areas do not carry Type-5. To originate externals
from *inside* an NSSA, use the per-area `redistribute` block, which
produces area-scoped Type-7 LSAs that the NSSA ABR translates to
Type-5 for the rest of the domain — see
[Area Types: Stub and NSSA](ch-08-13-ospf-area-types.md). Instance
and per-area redistribution share the same `metric` / `metric-type`
semantics.

## OSPFv3

`router ospfv3` has instance-level `redistribute bgp` only (no
instance-level `connected`) — its primary role is the SRv6 L3VPN
PE–CE "down" direction, where a PE injects the VPNv6 routes it
imported into a VRF into the CE-facing OSPFv3 instance. Per-area
NSSA `redistribute connected` is available for v3 exactly as for
v2.
