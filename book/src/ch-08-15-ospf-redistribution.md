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
| `static` | presence container | — (absent = off) |
| `kernel` | presence container | — (absent = off) |
| `isis` | presence container | — (absent = off) |
| `bgp` | presence container | — (absent = off) |
| `table` | list, key `id` (1..65535) | — (empty = off) |
| `<source>/metric` | uint32, 0..16777214 | 20 |
| `<source>/metric-type` | `type-1` \| `type-2` | `type-2` |
| `<source>/route-map` | string (policy name) | — (no filtering) |

Each source is a presence container — naming it enables
redistribution of that source, deleting it flushes the corresponding
Type-5s. Sources are independent subscriptions to the RIB, so any
combination can be active at once. The knobs also exist per VRF
instance, where the subscription is scoped so a VRF's OSPF sees only
that VRF's routes.

## Kernel routing tables (`redistribute table`)

`redistribute table <id>` — FRR's `redistribute table (1-65535)` —
imports the routes a specific **non-main kernel routing table**
holds, regardless of who installed them. This is the classic escape
hatch for advertising routes maintained outside the routing daemon:
policy-routing tables, routes injected by an external controller or
script via `ip route ... table N`, or tables populated by another
routing stack.

```
router ospf {
  redistribute {
    table 100 {
      metric 30;
      metric-type type-2;
      route-map RM;    # optional, same live-re-apply semantics
    }
  }
}
```

`table` is a list keyed by table ID, so several tables can be
redistributed at once, each with its own `metric` / `metric-type` /
`route-map`. The RIB watches the kernel table through netlink — the
startup route dump seeds it and the monitor tracks it live — so a
route added to the table while OSPF runs originates its Type-5
immediately, and a deleted one flushes it, without any daemon
restart. Configuring a `table` source makes the router an ASBR
exactly as the other sources do.

Two scope notes, both matching FRR: the `table` source exists on
**OSPFv2 only** (`ospf6d` has no `redistribute table`), and the
**main** table is not a valid target — routes there are covered by
the ordinary `kernel` / `static` / protocol sources.

Validated by `ospfv2_redist_table.feature`, which installs kernel
routes into table 100 both before the daemon starts (dump path) and
while it runs (monitor path), and asserts the externals appear on —
and, on deletion, disappear from — the neighbor.

## Route-map filtering

`route-map <name>` binds a policy list (the same `policy` /
`prefix-set` objects BGP uses) as the redistribution filter for that
source, mirroring FRR's `redistribute <proto> route-map <name>`:

```
prefix-set PS {
  prefix 10.1.0.0/16;
}
policy RM {
  entry 10 {
    action permit;
    match prefix-set PS;
    set med set 555;       # doubles as FRR's `set metric`
  }
}
router ospf {
  redistribute {
    connected {
      route-map RM;
    }
  }
}
```

Entries run in sequence order with FRR route-map semantics: an entry
with no `match prefix-set` matches everything, an entry naming an
undefined prefix-set never matches, and falling off the end of the
list is an **implicit deny** — so the map above admits only
`10.1.0.0/16` and drops every other connected prefix. A matching
entry's `set med` overrides the advertised external metric.
BGP-specific match clauses (communities, as-path, MED, origin, …)
never match a redistributed IGP route. Binding a `route-map` name
that has no definition is deny-all, matching FRR.

**Edits re-apply live.** OSPF subscribes to the policy engine's
change feed, so editing the policy list — or a prefix-set it
references — immediately re-filters the redistributed set: newly
permitted prefixes originate Type-5s, newly denied ones flush,
without touching adjacencies. Validated by
`ospfv2_redist_route_map.feature`, whose scenarios add and remove
prefixes from a live prefix-set and assert the externals appear and
disappear on the neighbor.

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

Instance-level Type-5s are originated with forwarding address
0.0.0.0, meaning traffic flows via the ASBR itself. NSSA Type-7s
originate with a non-zero FA where RFC 3101 §2.3 calls for one, and
received LSAs carrying a non-zero forwarding address are resolved
against the intra/inter-area route to the FA (RFC 2328 §16.4
step 3) — see [Area Types](ch-08-13-ospf-area-types.md) for the
full forwarding-address story.

## Default route origination

`default-information originate` advertises a Type-5 default
(0.0.0.0/0) from this router:

```
router ospf {
  default-information {
    originate {
      always true;
    }
  }
}
```

| YANG leaf (`/router/ospf/default-information/originate/…`) | Default | Notes |
|---|---|---|
| `originate` | presence | Makes the router an ASBR (E-bit set). |
| `always` | `false` | Originate unconditionally. |
| `metric` | 10 | FRR-parity default for the originated default (redistribute uses 20). |
| `metric-type` | `type-2` | E1/E2 semantics as for redistribution. |

Without `always`, the default is originated **only while a non-OSPF
default route exists in the RIB** — zebra-rs tracks this through a
dedicated RIB default-route watch, so a static or BGP default
appearing or disappearing originates or flushes the Type-5 without
any table-wide subscription. With `always`, it is advertised
unconditionally.

## Redistribution into NSSA areas

Stub and NSSA areas do not carry Type-5. To originate externals
from *inside* an NSSA, use the per-area `redistribute` block, which
produces area-scoped Type-7 LSAs that the NSSA ABR translates to
Type-5 for the rest of the domain — see
[Area Types: Stub and NSSA](ch-08-13-ospf-area-types.md). Instance
and per-area redistribution share the same `metric` / `metric-type`
semantics.

## OSPFv3

`router ospfv3` exposes the same five instance-level redistribute
sources (connected, static, kernel, isis, bgp) with the same
`metric` / `metric-type` / `route-map` leaves — including the live
route-map re-application. The `table` source is the one exception:
it is OSPFv2-only, matching FRR, where `ospf6d` has no
`redistribute table` either. The bgp source's flagship role is the SRv6
L3VPN PE–CE "down" direction, where a PE injects the VPNv6 routes it
imported into a VRF into the CE-facing OSPFv3 instance. Per-area
NSSA `redistribute connected` is available for v3 exactly as for
v2.
