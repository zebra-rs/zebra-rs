# Segment Routing (SR-MPLS)

OSPFv3 SR-MPLS follows RFC 8666: Prefix-SIDs ride the
E-Intra-Area-Prefix-LSA and Adj-SIDs the E-Router-LSA's Router-Link
TLV (RFC 8362 Extended LSAs), and the SR capabilities — SR-Algorithm,
SRGB, SRLB — ride the RFC 7770 Router Information LSA (LS type
`0xA00C`).
The configuration mirrors the OSPFv2 surface:

```
router ospfv3 {
  segment-routing {
    mpls;
  }
  area 0 {
    interface lo {
      enabled true;
      prefix-sid {
        index 100;
      }
    }
    interface enp0s6 {
      enabled true;
      network-type point-to-point;
    }
  }
}
```

| YANG leaf (`/router/ospfv3/…`) | Type | Notes |
|---|---|---|
| `segment-routing/mpls` | presence | Enables SR-MPLS: the Router Information LSA and the Prefix-SID / Adj-SID advertisements. |
| `area/<id>/interface/<n>/prefix-sid/index` \| `absolute` | uint32 | Prefix-SID for the interface's prefix (RFC 8666 §5); index and absolute are mutually exclusive. |
| `area/<id>/interface/<n>/adjacency-sid/index` \| `absolute` | uint32 | Staged configuration; dynamic Adj-SIDs are allocated automatically from the SRLB for every adjacency (RFC 8666 §6.2). |

The label blocks are the `default` entry of the global
`segment-routing block` (SRGB 16000..23999 and SRLB 15000..15999 unless
configured), the same block IS-IS and OSPFv2 read. A change to it is
followed at once: the Router Information LSA is re-originated, the own
Prefix-SID labels move with the SRGB, and the dynamic Adj-SIDs are drawn
again from a moved SRLB.

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
      enabled true;
      flex-algo-prefix-sid 128 {
        index 1100;
      }
    }
  }
}
```

The definition (FAD) is advertised in the Router Information LSA when
`advertise-definition true`; per-algo Prefix-SIDs come from the
per-interface `flex-algo-prefix-sid` list (algo 128..255), and link
affinities from the `affinity` leaf-list on participating
interfaces. `metric-type` selects `igp`,
`min-unidir-link-delay`, or `te-default`; `priority` (default 128)
orders competing FAD advertisements. The definition shape is identical
to OSPFv2's — only the carrier LSA differs.

**What a router computes with is the winning definition**, selected in
each area as OSPFv2 does (RFC 9350 §5.3; see
[OSPF Segment Routing](ch-08-09-ospf-segment-routing.md#flexible-algorithm)):
the highest `priority` among the definitions advertised in the area,
then the highest Router ID. This router's own definition is a candidate
in every area it advertises it in — its Router Information LSA,
originated while SR-MPLS or SRv6 is on. Participation is decided per area: in an
area whose winner it cannot support, or where no definition is
advertised, the router drops the algorithm from that area's SR-Algorithm
list, stops advertising the algorithm's Prefix-SIDs on the area's
interfaces, and computes no topology for it there. Definition edits take
effect at commit.

`show ospfv3 flex-algo` shows, for each algorithm and area, the
definition it is computed with and whether this router participates:

```
Flex-Algorithm 128
  Metric-Type: igp
  Priority: 100
  Advertise-Definition: true
  Area 0.0.0.0: definition from 10.0.0.2, priority 200; participating
```

The SR capabilities, definitions included, ride the OSPFv3 Router
Information LSA as RFC 8666 and RFC 9350 specify, and Adj-SIDs use RFC
8666's sub-TLV code points, so OSPFv3 Segment Routing and Flexible
Algorithm interoperate with other implementations.

Earlier releases carried the SR capabilities on an E-Router-LSA (Link
State ID 0) and sent the Adj-SID as sub-TLV 6 and the LAN Adj-SID as 7.
zebra-rs still reads both from older zebra-rs routers, and flushes its
own former E-Router-LSA. The oldest of those releases cannot read the
standard encodings: they drop a whole LS Update that carries a standard
LAN Adj-SID, and find no SR capabilities in a router that no longer
sends the E-Router-LSA. So in a network of zebra-rs routers, upgrade
them all from such a release together, or first to a release that reads
both encodings and still sends the former ones.
