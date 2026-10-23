# Interface Configuration

Interface attributes that are independent of any routing protocol live
under the top-level `interface` list, keyed by the kernel interface
name:

```
interface enp0s6 {
  mtu 1400;
  ipv4 {
    address 10.0.0.1/24;
  }
}
```

| YANG leaf | Type | Notes |
|---|---|---|
| `/interface/<name>/if-name` | `string` | List key — the kernel interface name. |
| `/interface/<name>/mtu` | `uint32` (68..65535) | Maximum transmission unit in bytes. See below. |
| `/interface/<name>/vrf` | leafref `/vrf/name` | Enslave the interface to a VRF master device. |
| `/interface/<name>/bridge` | leafref `/bridge/name` | Enslave the interface to a bridge master device. See below. |
| `/interface/<name>/ipv4/address` | leaf-list of `inet:ipv4-prefix` | IPv4 address(es) with prefix length — repeatable. See [Multiple IPv4 Addresses](ch-00-09-multi-address.md). |
| `/interface/<name>/ipv6/address` | `inet:ipv6-prefix` | IPv6 address (with prefix length). |

The list entry itself is not a separate "create interface" operation —
it just attaches configuration to a kernel device that already exists
(or appears later). zebra-rs does not create physical or virtual links
from this block; devices it does own come from their dedicated top-level
lists ([`bridge`](ch-00-04-bridge-configuration.md),
[`vxlan`](ch-00-03-vxlan-configuration.md),
[`vlan`](ch-00-08-vlan-configuration.md), `vrf`).

## Bridge and VRF enslavement

The `bridge` and `vrf` leaves enslave the interface to a master device —
the equivalent of `ip link set <name> master <master>`:

```
interface enp0s6 {
  bridge br0;     # make enp0s6 a port of the Linux bridge br0
}
interface enp0s7 {
  vrf CUST-A;     # move enp0s7 into the VRF CUST-A
}
```

Both write the kernel `IFLA_MASTER`, so they are mutually exclusive — an
interface has exactly one master. `bridge` is a leafref to
`/bridge/name` and `vrf` a leafref to `/vrf/name`; the referenced device
is the one zebra-rs creates from its own
[`bridge`](ch-00-04-bridge-configuration.md) / `vrf` block.

The bind is **staged**, the same way the configured MTU is: it is held
as durable desired-state and applied once *both* the interface and the
master device exist in the kernel, so the order of configuration and
device creation is irrelevant. If the bridge is configured after the
interface, the enslavement fires when the bridge appears; if the bridge
is later deleted, the kernel releases the port and zebra-rs re-applies
the bind automatically when the bridge is re-created.

Remove the binding with the master name as the argument:

```
no interface enp0s6 bridge br0
```

## MTU

The `mtu` leaf sets the interface MTU on the kernel. zebra-rs issues a
netlink `RTM_NEWLINK` (`IFLA_MTU`) — the equivalent of
`ip link set <name> mtu <n>`.

```
interface enp0s6 {
  mtu 1400;
}
```

### Default and range

When `mtu` is unset, the interface keeps whatever MTU the kernel
assigned it — typically **65536** for loopback devices and **1500**
for everything else.

The YANG schema constrains the configurable value to **68..65535**,
which is the IPv4 lower bound (RFC 791) up to the 16-bit ceiling.
The IPv6 minimum link MTU is **1280** (RFC 8200 §5): zebra-rs does not
reject sub-1280 values up front, because whether they are legal depends
on the interface's runtime state. Instead, the kernel is the authority
— see *Apply failures* below.

### Deleting the configuration

Deleting the leaf restores the MTU the interface had **before** it was
first configured (the value zebra-rs observed when it first learned the
interface), not a hard-coded default:

```
no interface enp0s6 mtu
```

If, for example, the kernel reported 1500 when the daemon started and
the operator configured 9000, then `no interface enp0s6 mtu` returns
the interface to 1500.

### Apply failures

A value the kernel refuses — most commonly an MTU below the IPv6
minimum of 1280 on an interface that has IPv6 enabled — is reported by
`show interface`. The live MTU line continues to show the value the
kernel actually has; a second line records the rejected attempt:

```
Interface: enp0s6
  Hardware is Ethernet 52:54:00:11:22:33
  index 2 metric 1 mtu 1500
  MTU set to 1000 is failed due to Invalid argument (os error 22)
  Link is Up
  ...
```

The failure note clears automatically the next time a set on that
interface succeeds.

### Configuring before the interface exists

The configured MTU is durable desired-state: it is kept even if the
named interface is absent, and re-applied automatically when a matching
interface appears (or re-appears after being removed and recreated).
This makes the order of `interface` configuration and device creation
irrelevant.

## Protocol synchronisation

Several protocols use the interface MTU when building packets, so a
change must reach them rather than being a kernel-only setting:

- **OSPF** stamps the Database Description packet's `Interface MTU`
  field with it (RFC 2328 §10.6); a mismatch with a neighbour stalls
  the adjacency in `ExStart` unless `mtu-ignore` is set.
- **IS-IS** pads Hello PDUs up to the MTU (RFC 1195 §8) and sizes LSP
  fragmentation against it.

When the MTU of a known interface changes — whether through this
configuration or an external `ip link set` — the RIB fans the new value
out to every protocol that has the interface. They update their cached
value in place, leaving adjacencies and state machines untouched, so
the change is non-disruptive. Each protocol's interface view reflects
the same value:

```
# show interface          → live kernel MTU
# show ospf interface  → "ifindex 2, MTU 1400 bytes, BW 0 Mbit ..."
# show isis interface detail → "Type: ..., SNPA: ..., MTU: 1400"
```

If these ever disagree it indicates the notification path was missed —
they are sourced from one RIB-driven update, not independent reads.

## Show commands

### `show interface [brief | <name>]`

`show interface` lists every interface in detail, `show interface <name>`
one. Each block holds:

- **`Hardware is`:** the link type, and an Ethernet interface's MAC
  address.
- **`index`, `metric` and `mtu`**, and the MTU apply error, if the last
  configured MTU failed (see [Apply failures](#apply-failures)).
- **`VLAN id <id> parent <name> (index <n>)`** for an 802.1Q
  sub-interface, whether created from the
  [`vlan`](ch-00-08-vlan-configuration.md) list or found in the kernel.
- **`Link is Up` or `Down`**, then the kernel's interface flags.
- **`VRF Binding`:** `vrf <name>`, or `Not bound`.
- **`Label switching`:** whether zebra-rs turned MPLS input on for the
  interface (`net.mpls.conf.<name>.input`). It stays `disabled` when the
  kernel has no MPLS support.
- **The addresses:** `inet` and `inet6`, each with `secondary`, a
  non-global scope, abnormal address state and finite lifetimes when
  they apply (see
  [Multiple IPv4 Addresses and the Secondary Flag](ch-00-09-multi-address.md)).
- **The kernel's counters** for the interface.

```
r1> show interface r1-r2
Interface: r1-r2
  Hardware is Ethernet c2:19:e4:c5:6c:97
  index 2 metric 1 mtu 1500
  Link is Up
  Up | Broadcast | Running | Multicast | LowerUp
  VRF Binding: Not bound
  Label switching is enabled
  inet 192.168.12.1/24
  inet6 fe80::c019:e4ff:fec5:6c97/64 scope link
  inet6 2001:db8:12::1/64
    input packets 174, bytes 21040, dropped 0, multicast packets 0
    input errors 0, frame 0, fifo 0, compressed 0
    output packets 188, bytes 22428, dropped 0
    output errors 0, carrier 0, fifo 0, compressed 0
    collisions 0

r1> show interface r1-r2.100
Interface: r1-r2.100
  Hardware is Ethernet c2:19:e4:c5:6c:97
  index 8 metric 1 mtu 1500
  VLAN id 100 parent r1-r2 (index 2)
  Link is Up
  Up | Broadcast | Running | Multicast | LowerUp
  VRF Binding: Not bound
  Label switching is enabled
  inet 10.100.0.1/24
  inet6 fe80::c019:e4ff:fec5:6c97/64 scope link
    input packets 0, bytes 0, dropped 0, multicast packets 0
...
```

`show interface brief` gives one line per interface, with its status,
VRF and addresses:

```
r1> show interface brief
Interface        Status VRF            Addresses
---------        ------ ---            ---------
lo               Up     default        127.0.0.1/8
                                       10.0.0.1/32
                                       ::1/128
                                       2001:db8::1/128
r1-r2            Up     default        192.168.12.1/24
                                       fe80::c019:e4ff:fec5:6c97/64
                                       2001:db8:12::1/64
r1-r3            Up     default        192.168.13.1/24
                                       fe80::849b:87ff:fe25:d05e/64
                                       2001:db8:13::1/64
r1-v             Up     blue           192.168.120.1/24
                                       fe80::2021:ffff:fe1f:e931/64
d1               Up     default        172.16.1.1/24
                                       fe80::c8ff:4fff:fe07:2956/64
                                       2001:db8:f1::1/64
sr0              Up     default        fe80::d4fa:15ff:fe79:3fb3/64
blue             Up     default
r1-r2.100        Up     default        10.100.0.1/24
                                       fe80::c019:e4ff:fec5:6c97/64
```

JSON: a list of interface objects. The brief view carries `interface`,
`status`, `vrf` and `addresses`. The detailed view carries `interface`,
`hardware`, `index`, `metric`, `mtu`, `link_status`, `flags`,
`vrf_binding`, `label_switching`, `inet_addresses` and
`inet6_addresses`, each address with `address`, `scope` and (IPv4 only)
`secondary`. Optional fields appear only when they apply: `mac_address`,
`mtu_error`, an address's `flags`, `valid_lft` and `preferred_lft`, and
a VLAN sub-interface's `vlan_id`, `parent` (the parent's name) and
`parent_index`. The counters are in the text view only.

### `show vrf`

Every VRF, with its kernel table ID, its Router ID (see
[Router ID Selection](ch-00-01-router-id.md#per-vrf-router-id)) and its
member interfaces:

```
r1> show vrf
 Name                      Table-ID  Router-ID        Members
 ----------------------  ----------  ---------------  --------------------------------
 blue                             1  192.168.120.1    r1-v
```

JSON: `{ "vrfs": [ { "name", "table_id", "router_id", "members" } ] }`,
where `router_id` is `null` for a VRF with no Router ID yet.

### `show ipv6 nd`

What the IPv6 Neighbor Discovery task sees on each interface, one line
per interface: whether it sends Router Advertisements, how many
neighbors it has heard from, and the ND packets received and sent:

```
r1> show ipv6 nd
Interface            RA   Neighbors   RX-total TX-total  Ifindex
r1-r2                on           1          7        3        2
r1-r3                off          1          3        0        3
```

JSON: a list of `{ name, ifindex, ra_enabled, neighbor_count, rx_total,
tx_total }`.

### `show ipv6 nd interface [<ifname>]`

One block per interface, or for `<ifname>` only:

- **The Router Advertisement scheduler**, when the interface sends RAs:
  the interval range, router lifetime, hop limit and M/O flags, the
  initial RAs still to send, when the next unsolicited one goes out,
  whether a solicited reply is pending, and when the last multicast RA
  went. Instead of a countdown, the next unsolicited RA reads
  `suspended (link down)` while the link is down, and `held (…)` while
  the interface has no link-local an RA can be sent from:
  `held (link-local not ready)` for the second or two DAD takes after
  `ip link set … up`, `held (no link-local)` when it has none at all,
  and `held (link-local failed DAD)` when another node on the link
  uses its address. The last does not clear by itself: change the
  address, and the daemon logs a warning when it happens. The initial
  RAs restart once a link-local is usable, and go out from the lowest
  usable one. A send that fails anyway is retried after half a second,
  doubling to 16 s while it keeps failing.
- **The daemon's counters**: Router and Neighbor Solicitations and
  Advertisements it received and RAs it sent, and the packets it dropped
  (hop limit not 255, malformed, or from a new source once the
  neighbor table is full).
- **The kernel's ICMPv6 counters** for the same four message types.
- **Each neighbor heard from**: how many of each message it sent, when
  it was first and last heard, and what its last RA carried.

```
r1> show ipv6 nd interface r1-r2
Interface r1-r2 (ifindex 2)
  Router advertisement: enabled
    interval 200-600s, lifetime 1800s, hop-limit 64, managed=0 other=0
    initial advertisements remaining 0, next unsolicited in 4m53s
    solicited reply pending: no, last multicast 1m52s ago
  Counters (daemon-observed)        Sent  Received
    Router solicitations               -         0
    Router advertisements              3         3
    Neighbor solicitations             -         2
    Neighbor advertisements            -         2
    dropped: hop-limit 0, malformed 0, untracked sources 0
  Counters (kernel)                 Sent  Received
    Router solicitations               0         0
    Router advertisements              3         3
    Neighbor solicitations             4         2
    Neighbor advertisements            2         2
  Neighbors (1):
    fe80::e0c6:66ff:fe83:4ae8 RA 3  RS 0  NS 2  NA 2   first 2m30s ago, last 1m52s ago
      last RA: lifetime 1800s hop-limit 64 M=0 O=0
```

JSON: a list of `{ name, ifindex, ra_enabled, ra_scheduler, counters,
kernel_counters, neighbors }`. `ra_scheduler` holds the scheduler
fields above (`min_interval_secs`, `max_interval_secs`,
`router_lifetime`, `cur_hop_limit`, `managed`, `other`,
`initial_remaining`, `suspended`, `waiting_for_link_local`,
`link_local_hold` (`missing`, `not_ready` or `dad_failed` while held,
otherwise `null`), `next_unsolicited_in_secs` (`null` while suspended
or held),
`solicited_pending`, `last_multicast_secs_ago`); each neighbor has
`address`, `first_seen_secs`, `last_seen_secs`, its `rx_*` counts and
its `last_ra_*` values.

## Cross-reference — FRR / iproute2

| zebra-rs | FRR `interface` / iproute2 |
|---|---|
| `interface <n> mtu <v>` | `mtu <v>` (interface) / `ip link set <n> mtu <v>` |
| `no interface <n> mtu` | restore original — no direct FRR equivalent (FRR leaves the last value) |
| `interface <n> ipv4 address <p>` | `ip address <p>` (interface) |
| `interface <n> vrf <name>` | `ip link set <n> master <name>` (VRF master) |
| `interface <n> bridge <name>` | `ip link set <n> master <name>` (bridge master) |

Note the delete semantics differ: zebra-rs restores the
originally-observed MTU, whereas iproute2/FRR simply leave whatever was
last set in place.
