# Multi-Area Routing and the ABR

A router with enabled interfaces in two or more areas is an Area
Border Router. There is nothing to configure: ABR status is derived
from the `area` list (RFC 2328 §3.3 — areas with no attached links
don't count), the B-bit is set in the Router-LSA of every attached
area, and inter-area Type-3/Type-4 Summary origination follows
automatically.

```
router ospf {
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

With this on the ABR (and plain single-area configs on the internal
routers), routers inside area 0.0.0.1 learn the other areas'
prefixes as inter-area routes in `show ospf route`, and the LSDB
shows the ABR's Type-3 Summary-LSAs.

## Type-3 Summary origination

After each SPF run the ABR derives the desired Type-3 set from its
routing table and diff-syncs it into every attached area
(RFC 2328 §12.4.3) — unchanged summaries are not re-flooded, and
origination never schedules SPF itself, so there is no
SPF → summary → SPF cycle. The direction rules implement the
standard backbone split-horizon:

- Intra-area routes of any attached area are summarized into every
  *other* attached area.
- Inter-area routes are summarized only from the **backbone into
  non-backbone areas** — never back into area 0, and never from one
  non-backbone area into another. This is the RFC 2328 loop
  prevention that makes the backbone mandatory for inter-area
  transit.
- A prefix the destination area already reaches intra-area is
  skipped; when several source areas offer the same prefix the
  lowest metric wins.
- Areas configured `no-summary` (totally-stubby / totally-NSSA —
  see [Area Types](ch-08-13-ospf-area-types.md)) receive no Type-3
  at all.

## Area ranges

`area <id> range <prefix>` condenses an area's own intra-area
routes at the ABR (RFC 2328 §12.4.3): components falling inside a
configured range are not advertised individually — one aggregate
Type-3 is originated instead, as long as at least one component
exists.

```
router ospf {
  area 0.0.0.1 {
    range 10.1.0.0/16;
    range 10.9.0.0/16 {
      not-advertise true;
    }
    interface enp0s7 {
      enable true;
    }
  }
}
```

| YANG leaf (`/router/ospf/area/<id>/range/<prefix>/…`) | Default | Notes |
|---|---|---|
| `<prefix>` | list key | The aggregate to advertise. |
| `not-advertise` | `false` | Hide the whole range — no aggregate, no components. |
| `cost` | — (largest component) | Fixed aggregate metric instead of the RFC's largest-component rule. |

The most-specific configured range wins when several contain a
component. Ranges apply only to the area's own intra-area routes —
inter-area routes re-advertised from the backbone pass through
unaffected — and prefixes outside every range keep advertising
individually.

### Discard route

Advertising one aggregate for a whole range means the ABR draws
traffic for *every* address in the range, including sub-prefixes
that no component actually covers. Without protection that traffic
would fall through to the ABR's own default route and could loop
straight back. RFC 2328 §12.4.3 closes the hole with a companion
*discard* route: while a range is active the ABR installs a
blackhole covering the aggregate, so a packet to a non-existent
component is dropped locally instead of forwarded.

zebra-rs installs this discard through the RIB `nexthop blackhole`
type (kernel `RTN_BLACKHOLE`, the same primitive as
[static blackhole routes](ch-01-03-blackhole-static-route.md)):

```
$ ip route show 10.1.0.0/16
blackhole 10.1.0.0/16 proto ospf
```

The discard is more general (shorter prefix) than every component,
so real destinations still match their specific intra-area route by
longest-prefix; only the gaps hit the blackhole. It is installed for
every active range — including `not-advertise` ranges, since hiding
the aggregate from neighbors does not remove the local loop
exposure — and withdrawn as soon as the range loses its last
component or the router stops being an ABR. A range prefix that a
real OSPF route already reaches exactly is left alone rather than
blackholed.

## Type-4 ASBR-Summary origination

Router-LSAs are area-scoped, so a router in area 1 cannot see the
E-bit (ASBR flag) of an ASBR sitting in area 0 — without help it
could not compute routes for that ASBR's Type-5 externals. The ABR
closes the gap (RFC 2328 §12.4.3): for every Router-LSA with the
E-bit set in one attached area it originates a Type-4 ASBR-Summary
into the others, carrying the ABR's own SPF cost to that ASBR.

On the consuming side, when an AS-External LSA's advertising router
is not in the local area's SPF result, route computation falls back
to a Type-4 with a matching Link-State ID (RFC 2328 §16.4 step 5)
and uses `cost-to-ABR + Type-4 metric` as the path to the ASBR,
picking the cheapest advertising ABR. This is what makes E1
external metrics come out right across area boundaries — see
[Route Redistribution](ch-08-15-ospf-redistribution.md).

## OSPFv3

OSPFv3 implements the same ABR machinery using its own LSA types —
Inter-Area-Prefix-LSAs (0x2003) in place of Type-3 and
Inter-Area-Router-LSAs (0x2004) in place of Type-4, with identical
direction rules, diff-gating, and receive-side computation. See
[the OSPFv3 chapter's Multi-Area page](ch-15-04-ospfv3-multi-area-abr.md).
