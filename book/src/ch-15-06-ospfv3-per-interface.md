# Per-Interface Configuration

Each `interface` entry under an OSPFv3 area carries the same
per-link tuning parameters as OSPFv2, with identical defaults (the
YANG leaves are shared-shape; the defaults live in the common OSPF
core). Timers are covered separately in
[Timer Configuration](ch-15-07-ospfv3-timers.md), the SR knobs
(`prefix-sid`, `adjacency-sid`, `flex-algo-prefix-sid`) in
[Segment Routing](ch-15-10-ospfv3-segment-routing.md), and the
`bfd` block in [BFD](ch-15-17-ospfv3-bfd.md).

| YANG leaf (`/router/ospfv3/area/<id>/interface/<n>/…`) | Default | Range |
|---|---|---|
| `enable` | `false` | boolean |
| `network-type` | `broadcast` | `broadcast` \| `point-to-point` |
| `priority` | 64 | 0..255 |
| `cost` | 10 | 0..65535 |
| `mtu-ignore` | `false` | boolean |
| `passive` | `false` | boolean |
| `affinity` | — | leaf-list of `/affinity-map` names |

Notes:

- **`enable`** is the participation switch, as in v2. The interface
  additionally needs an IPv6 link-local address before any packet
  is sent — normally automatic the moment the link is up.
- **`network-type`** mirrors the v2 knob: `point-to-point` skips
  Waiting and DR election; changing it on a live interface bounces
  the IFSM through an internal `Disable → Enable` pair. NBMA and
  point-to-multipoint are deliberately not supported: they serve
  legacy WAN fabrics (Frame Relay, X.25, ATM), which modern
  Ethernet networks no longer use.
- **`priority`** is the DR-election priority carried in v3 Hellos
  (and recorded in the Link-LSA). Semantics as v2: higher wins,
  zero forbids DR/BDR.
- **`cost`** is the SPF edge weight. Because OSPFv3 splits topology
  and addressing, a cost change re-originates *three* LSAs — the
  Router-LSA (topology metric), the Intra-Area-Prefix-LSA (prefix
  metric), and the E-Intra-Area-Prefix-LSA when segment routing is
  enabled — and schedules SPF, so it takes effect immediately.
  Loopback prefixes are always advertised at metric 0 regardless of
  `cost`, matching v2/FRR/Junos convention.
- **`mtu-ignore`** disables the MTU-mismatch check in the DBD
  exchange, as in v2.
- **`passive`** advertises the interface's prefixes (via the
  Intra-Area-Prefix-LSA) while sending and accepting no Hellos, so
  no adjacency forms on the segment. Loopbacks are implicitly
  passive. Semantics as in
  [the v2 page](ch-08-07-ospf-per-interface.md).
- **`affinity`** attaches named admin-group bits (from the global
  `/affinity-map`) to the link, advertised in the RFC 9492 ASLA
  sub-TLV of the E-Router-LSA — consumed by
  [Flex-Algo](ch-15-10-ospfv3-segment-routing.md) constraints.
- **`instance-id`** (0..255, default 0) sets the RFC 5340 §A.3.1
  OSPFv3 Instance ID stamped into every packet sent on the link;
  received packets whose Instance ID differs are dropped (§8.2).
  This separates multiple OSPFv3 instances sharing one link — both
  ends of an adjacency must configure the same value, and a
  mismatch simply never forms a neighbor. Shown by
  `show ospfv3 interface`; validated by
  `ospfv3_instance_id.feature` (matched and mismatched scenarios).

The v2-only `te-metric` block (RFC 7471 delay/loss attributes and
the STAMP measurement hook) has no OSPFv3 counterpart yet.
