# Segment Routing (SR-MPLS)

OSPFv3 SR-MPLS follows RFC 8666: the Segment Routing extensions
ride the RFC 8362 Extended LSAs — Prefix-SIDs in the
E-Intra-Area-Prefix-LSA, Adj-SIDs in the E-Router-LSA's Router-Link
TLV, and the SR capabilities (SRGB) in an SR-info E-Router-LSA.
The configuration mirrors the OSPFv2 surface:

```
router ospfv3 {
  segment-routing {
    mpls;
  }
  area 0 {
    interface lo {
      enable true;
      prefix-sid {
        index 100;
      }
    }
    interface enp0s6 {
      enable true;
      network-type point-to-point;
    }
  }
}
```

| YANG leaf (`/router/ospfv3/…`) | Type | Notes |
|---|---|---|
| `segment-routing/mpls` | presence | Enables E-Router-LSA / SR-info origination. |
| `area/<id>/interface/<n>/prefix-sid/index` \| `absolute` | uint32 | Prefix-SID for the interface's prefix (RFC 8666 §5); index and absolute are mutually exclusive. |
| `area/<id>/interface/<n>/adjacency-sid/index` \| `absolute` | uint32 | Staged configuration; dynamic Adj-SIDs are allocated automatically from the SRLB for every adjacency (RFC 8666 §6.2). |

The label blocks come from the global `segment-routing block`
definitions (SRGB default 16000+, SRLB default 15000+), shared with
IS-IS and OSPFv2.

## TI-LFA

Topology-Independent LFA computes a post-convergence, loop-free
repair path per destination and pre-installs it as a backup; with
`segment-routing mpls` the repair is expressed as an SR-MPLS label
stack (node SID plus SRLB Adj-SIDs as needed):

```
router ospfv3 {
  segment-routing {
    mpls;
  }
  fast-reroute {
    ti-lfa;
  }
}
```

`fast-reroute` carries an optional `compute-mode` (`serial`,
`conservative`, `aggressive`, or `sharding` with `shards 1..256`,
default 8) controlling how the per-destination computation is
parallelized, and a `backup-as-primary` presence knob. Inspect the
results with `show ospfv3 ti-lfa` (graph-level view) and
`show ospfv3 repair-list [detail]` (per-segment label breakdown —
`detail` shows the full stack). TI-LFA also works with the SRv6
dataplane; see [SRv6](ch-15-11-ospfv3-srv6.md).

## Flexible Algorithm (RFC 9350)

Flex-Algo constrains SPF to links satisfying an admin-group /
SRLG / metric-type policy, per algorithm number:

```
router ospfv3 {
  flex-algo 128 {
    advertise-definition true;
    metric-type igp;
    dataplane {
      sr-mpls true;
    }
    affinity {
      exclude-any RED;
    }
  }
  area 0 {
    interface lo {
      enable true;
      flex-algo-prefix-sid 128 {
        index 1100;
      }
    }
  }
}
```

The definition (FAD) is advertised in the E-Router-LSA when
`advertise-definition true`; per-algo Prefix-SIDs come from the
per-interface `flex-algo-prefix-sid` list (algo 128..255), and link
affinities from the `affinity` leaf-list on participating
interfaces. `metric-type` selects `igp`,
`min-unidir-link-delay`, or `te-default`; `priority` (default 128)
orders competing FAD advertisements. State is visible under
`show ospfv3 flex-algo`. The definition shape is identical to
OSPFv2's — only the carrier LSA differs.
