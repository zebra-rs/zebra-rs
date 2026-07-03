# Cross-Reference with FRR ospf6d

For operators arriving from FRR, this table maps the zebra-rs
OSPFv3 YANG configuration surface to the equivalent FRR `ospf6d`
commands. The structural difference matches the v2 chapter's:
zebra-rs declares interfaces under their area, while FRR binds an
interface to an area with a per-interface command.

| zebra-rs YANG (`router ospfv3 …`) | FRR `ospf6d` command |
|---|---|
| `router-id` | `ospf6 router-id` |
| `area/<id>/interface/<n>/enable true` | `ipv6 ospf6 area <id>` (interface) |
| `area/<id>/interface/<n>/network-type point-to-point` | `ipv6 ospf6 network point-to-point` (interface) |
| `area/<id>/interface/<n>/priority` | `ipv6 ospf6 priority` (interface) |
| `area/<id>/interface/<n>/cost` | `ipv6 ospf6 cost` (interface) |
| `area/<id>/interface/<n>/hello-interval` | `ipv6 ospf6 hello-interval` (interface) |
| `area/<id>/interface/<n>/dead-interval` | `ipv6 ospf6 dead-interval` (interface) |
| `area/<id>/interface/<n>/retransmit-interval` | `ipv6 ospf6 retransmit-interval` (interface) |
| `area/<id>/interface/<n>/mtu-ignore` | `ipv6 ospf6 mtu-ignore` (interface) |
| `area/<id>/interface/<n>/passive true` | `ipv6 ospf6 passive` (interface) |
| `area/<id>/area-type stub` | `area <id> stub` |
| `area/<id>/area-type nssa` | `area <id> nssa` |
| `area/<id>/no-summary true` | `area <id> stub no-summary` / `area <id> nssa no-summary` |
| `area/<id>/range <prefix> { not-advertise; cost; }` | `area <id> range <prefix> [not-advertise \| cost <c>]` |
| `redistribute <connected\|static\|kernel\|isis\|bgp> { metric; metric-type; }` | `redistribute <source> metric <m> metric-type <1\|2>` |
| `default-information originate { always; metric; metric-type; }` | `default-information originate [always] [metric <m>] [metric-type <1\|2>]` |
| `clear ospfv3 neighbor` | `clear ipv6 ospf6 interface [IFNAME]` |
| `graceful-restart helper-enabled` | `graceful-restart helper enable` |
| `graceful-restart helper-strict-lsa-checking` | `graceful-restart helper strict-lsa-checking` |
| `graceful-restart max-grace-period` | `graceful-restart helper supported-grace-time` |
| `clear ospfv3 graceful-restart begin` + `commit` | `graceful-restart prepare ipv6 ospf` (vtysh) |
| `show ospfv3 neighbor / database / route` | `show ipv6 ospf6 neighbor / database / route` |

Segment Routing has no `ospf6d` counterpart: FRR's `ospf6d` does not
implement SR-MPLS (RFC 8666), SRv6 (RFC 9513), TI-LFA, or
Flexible Algorithm, so the zebra-rs knobs under
`segment-routing`, `fast-reroute`, and `flex-algo` have no mapping.
Conversely, `ospf6d` features missing from zebra-rs are listed in
[Gaps Relative to FRR ospf6d](ch-15-15-ospfv3-frr-gaps.md).
