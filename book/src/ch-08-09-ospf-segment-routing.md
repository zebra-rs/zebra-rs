# Segment Routing

OSPFv2 SR-MPLS (RFC 8665) is configured at instance and per-interface
scope:

```
router ospf {
  segment-routing mpls;
  area 0 {
    interface enp0s6 {
      enabled true;
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

## Flexible Algorithm

A Flexible Algorithm (RFC 9350) is a constrained topology computed
alongside the regular one, reached through its own Prefix-SIDs. The
configuration mirrors IS-IS — see
[Flexible Algorithm (Flex-Algo)](ch-07-11-isis-flexalgo.md) for the
affinity map, link colors and constraint semantics:

```
router ospf {
  flex-algo 128 {
    advertise-definition true;
    priority 200;
    dataplane { sr-mpls true; }
    affinity { exclude-any blue; }
  }
  area 0.0.0.0 {
    interface lo {
      prefix-sid { index 1; }
      flex-algo-prefix-sid 128 { index 1281; }
    }
    interface eth0 {
      affinity blue;
    }
  }
}
```

**Creating a `flex-algo <n>` entry makes this router a candidate
participant; what it computes with is the winning definition.** Among
the definitions advertised in the area — this router's own among them,
if it has `advertise-definition true` — the highest `priority` wins, and
a tie goes to the highest Router ID (RFC 9350 §5.3). Every router selects
from the same LSDB, so every router computes the same topology. A
definition configured but not advertised is never a candidate. zebra-rs
advertises its definitions in the backbone's Router Information LSA, with
Segment Routing enabled.

A router **stops participating** when no definition is advertised, or
when the winner asks for something zebra-rs cannot compute: a
`te-default` metric-type, the M flag (`prefix-metric`), an SRLG
exclusion, a calculation type other than SPF, or a sub-TLV or flag it
does not know or cannot read. It then drops the algorithm from its
SR-Algorithm list, stops advertising the algorithm's Prefix-SIDs, and
removes the algorithm's routes and labels.

Definition edits take effect at commit: the Router Information LSA is
re-originated and every area recomputed.

`show ospf flex-algo` gives, for each algorithm and area, the definition
it is computed with and whether this router participates:

```
Flex-Algorithm 128
  Metric-Type: igp
  Priority: 100
  Advertise-Definition: true
  Area 0.0.0.0: definition from 10.0.0.2, priority 200; participating
```
