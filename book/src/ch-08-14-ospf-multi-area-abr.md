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

There is no `area range` prefix aggregation yet — each routing
table entry becomes its own Type-3 (see
[Gaps Relative to FRR ospfd](ch-08-12-ospf-frr-gaps.md)).

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

OSPFv3 supports multi-area topologies at the adjacency and
intra-area level — the instance originates one Router-LSA per
attached area (RFC 5340 §3.4.3), so non-backbone areas form
adjacencies and run SPF normally, and NSSA translation works
per-area. However, **ABR summary origination is not yet implemented
for v3**: an OSPFv3 ABR floods and displays Inter-Area-Prefix
(0x2003) and Inter-Area-Router (0x2004) LSAs received from others
but does not originate them, so v3 inter-area reachability through
a zebra-rs ABR is a known gap.
