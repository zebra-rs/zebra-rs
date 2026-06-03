# Route Redistribution

Redistribution injects routes that IS-IS did not learn itself —
connected interfaces, static routes, BGP, or OSPF — into the IS-IS
link-state database as **external reachability**, so the rest of the
area can reach a prefix that lives outside the IS-IS domain. The
originating router advertises each redistributed prefix as an Extended
IP Reachability entry in its own LSP; every other router runs SPF
against it and installs it like any other IS-IS route.

A typical use is an edge router that has a static route to a host (or a
stub network) which itself runs no IS-IS. Redistributing that static
route makes the host's prefix reachable from every router in the area
without extending IS-IS onto the edge link.

## Configuration

Redistribution is configured **per address family**, under the
`afi-safi` list of `router isis`. Each `redistribute` block is a
presence container holding one presence container per source:

```text
router isis {
  afi-safi ipv4 {
    redistribute {
      static {
        level level-1;
      }
    }
  }
}
```

The four sources are:

| Source      | Redistributes                                  |
|---          |---                                             |
| `connected` | Directly-connected interface prefixes          |
| `static`    | Static routes (`router static`)                |
| `bgp`       | BGP-learned routes                             |
| `ospf`      | OSPF-learned routes (with an optional match)   |

Enabling a source subscribes IS-IS to the matching route type in the
central RIB; routes the RIB delivers are stored and folded into the
self-originated LSP at the next re-origination. Removing the presence
container unsubscribes and re-originates the LSP without those
prefixes, withdrawing them from the area.

## The `level` default — read this first

Each source takes a `level` that selects which level's LSP carries the
redistributed prefix:

```text
level {level-1 | level-2 | level-1-2}
```

The default is **`level-2`**, matching IOS-XR. This is the most common
operational surprise: in a **Level-1-only** network, leaving `level`
at its default means the prefix is originated into the (non-existent)
Level-2 LSP and **never propagates**. An L1-only deployment must set
`level level-1` explicitly:

```text
router isis {
  is-type level-1;
  afi-safi ipv4 {
    redistribute {
      static { level level-1; }
    }
  }
}
```

`level-1-2` originates the prefix into both levels.

## Metric and metric-type

```text
metric <0..16777215>;
metric-type {internal | external | rib-metric-as-internal | rib-metric-as-external};
```

`metric-type` (default `internal`) selects where the advertised metric
comes from and, for IPv6, whether the external bit is set:

- `internal` / `external` — advertise the static `metric` value if one
  is configured, otherwise fall back to the source route's RIB cost.
- `rib-metric-as-internal` / `rib-metric-as-external` — always lift the
  source route's RIB cost into the IS-IS metric, ignoring any `metric`
  override.

The `external` and `rib-metric-as-external` variants set the **X (up/
down/external) bit** on the IPv6 reachability TLV (RFC 5308 §2) so a
receiver can tell the prefix originated outside IS-IS. The IPv4
Extended IP Reachability TLV (135) has no equivalent I/E bit, so for
IPv4 `metric-type` only chooses the metric source — the prefix is
carried the same way either way.

## Filtering OSPF by route subtype

The `ospf` source accepts a `match` filter that narrows which OSPF
route subtypes are pulled in:

```text
router isis {
  afi-safi ipv4 {
    redistribute {
      ospf {
        level level-1;
        match { type external; }
      }
    }
  }
}
```

`type` may list any of `internal` (intra-area + inter-area),
`external` (Type-5 LSA external 1/2), and `nssa-external` (Type-7 NSSA
external 1/2). An empty match (the default) pulls in every OSPF route.

## Wire encoding

Redistributed prefixes ride the same reachability TLVs as IS-IS's own
interface and `network` prefixes:

| Family       | TLV  | Notes                                       |
|---           |---   |---                                          |
| IPv4         | 135  | Extended IP Reachability (RFC 5305)         |
| IPv6         | 236  | IPv6 Reachability (RFC 5308); X-bit per type |
| IPv6 (MT 2)  | 237  | MT IPv6 Reachability when multi-topology is on |

Because external prefixes share the TLV space with internal ones, a
receiver does not, for IPv4, distinguish a redistributed prefix from a
native IS-IS one purely from the wire — both resolve through normal
SPF. Distinguishing the source is what the IPv6 X-bit provides.

## Worked example

A border router `r1` holds a static route to an edge host's loopback
`10.1.1.1/32` over a link that is *not* an IS-IS interface, and
redistributes it into a Level-1 area:

```text
router static {
  ipv4 {
    route 10.1.1.1/32 {
      nexthop 10.1.0.2;
    }
  }
}
router isis {
  net 49.0001.0000.0000.0001.00;
  is-type level-1;
  afi-safi ipv4 {
    redistribute {
      static { level level-1; }
    }
  }
}
```

Every other router in area 49.0001 then learns `10.1.1.1/32` as an
external reachability and installs it. Withdrawing the `redistribute
static` block (leaving the static route in place) re-originates r1's
LSP without the prefix, and the area drops the route within one SPF
cycle — r1 still reaches the host locally through its static route.

## Verification

The redistributed prefix appears in the per-level IS-IS routing table
and, once installed, in the central RIB:

```text
zebra# show isis route
...
L1 10.1.1.1/32 [metric 20]
  ...

zebra# show ip route
...
i L1 10.1.1.1/32 [115/20] via ...
```

On the originating router the prefix is reachable through the
underlying static (or connected/BGP/OSPF) route, so it will not appear
in that router's *IS-IS* route table — only on the routers that learned
it from the LSP.

To confirm a prefix was actually placed into (or removed from) the
**originating** router's self-LSP, look at its own LSP body, which
`show isis database detail` prints TLV-by-TLV. The redistributed prefix
shows up as an Extended IP Reachability entry under r1's LSP (the one
flagged `*`):

```text
zebra# show isis database detail
...
r1.00-00  *  ...
  ...
  Extended IP Reachability: 10.1.1.1/32 (Metric: 0)
```

This is the authoritative check for redistribution and withdrawal: `no
redistribute` must make that line disappear from the originator's own
LSP, not merely from some downstream router's route table.

This behaviour is exercised end-to-end by the `isis_redist` BDD feature
(`bdd/tests/features/isis-redist.feature`), which redistributes a
static route into a five-router Level-1 area, confirms it lands in r1's
self-originated LSP and that every router installs it, fails it over
onto a backup path, and verifies `no redistribute` clears the prefix
from r1's own LSP (and therefore from the whole area).
