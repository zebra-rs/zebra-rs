# Cross-Reference with FRR ospfd

For operators arriving from FRR, this table maps the zebra-rs YANG
configuration surface to the equivalent FRR `ospfd` commands.

| zebra-rs YANG | FRR `ospfd` command |
|---|---|
| `router-id` | `ospf router-id` |
| `area/<id>/interface/<n>/enable true` | `network <prefix> area <id>` (interface inferred from prefix) |
| `area/<id>/interface/<n>/priority` | `ip ospf priority` (interface) |
| `area/<id>/interface/<n>/hello-interval` | `ip ospf hello-interval` (interface) |
| `area/<id>/interface/<n>/dead-interval` | `ip ospf dead-interval` (interface) |
| `area/<id>/interface/<n>/retransmit-interval` | `ip ospf retransmit-interval` (interface) |
| `area/<id>/interface/<n>/mtu-ignore` | `ip ospf mtu-ignore` (interface) |
| `area/<id>/interface/<n>/passive true` | `ip ospf passive` (interface) |
| `area/<id>/interface/<n>/network-type point-to-point` | `ip ospf network point-to-point` (interface) |
| `area/<id>/interface/<n>/cost` | `ip ospf cost` (interface) |
| `area/<id>/area-type stub` | `area <id> stub` |
| `area/<id>/area-type nssa` | `area <id> nssa` |
| `area/<id>/no-summary true` | `area <id> stub no-summary` / `area <id> nssa no-summary` |
| `area/<id>/nssa-default-originate true` | `area <id> nssa default-information-originate` |
| `area/<id>/nssa-suppress-fa true` | `area <id> nssa suppress-fa` |
| `area/<id>/nssa-translator-role` | `area <id> nssa translate-candidate` / `translate-always` / `translate-never` |
| `area/<id>/range <prefix> { not-advertise; cost; }` | `area <id> range <prefix> [not-advertise \| cost <c>]` |
| `redistribute <connected\|static\|kernel\|isis\|bgp> { metric; metric-type; }` | `redistribute <source> metric <m> metric-type <1\|2>` |
| `default-information originate { always; metric; metric-type; }` | `default-information originate [always] [metric <m>] [metric-type <1\|2>]` |
| `area/<id>/interface/<n>/authentication simple` + `authentication-key` | `ip ospf authentication` + `ip ospf authentication-key` (interface) |
| `area/<id>/interface/<n>/authentication message-digest` + `message-digest-key <id> { md5; }` | `ip ospf authentication message-digest` + `ip ospf message-digest-key <id> md5 <key>` (interface) |
| `area/<id>/interface/<n>/key-chain` | `ip ospf authentication key-chain <name>` (interface) |
| `graceful-restart helper-enabled` | `graceful-restart helper enable` |
| `graceful-restart helper-strict-lsa-checking` | `graceful-restart helper strict-lsa-checking` |
| `graceful-restart max-grace-period` | `graceful-restart helper supported-grace-time` |
| `clear ospf graceful-restart begin` + `commit` | `graceful-restart prepare ip ospf` (vtysh) |
| `segment-routing mpls` | `segment-routing on` + `segment-routing mpls` |
| `area/<id>/interface/<n>/prefix-sid/index` | `ip ospf prefix-sid index` (interface) |

The shape differs: zebra-rs declares interfaces under their area
directly, while FRR uses a separate `network` statement to bind
prefix-matched interfaces to an area. The resulting on-the-wire
behaviour is the same.
