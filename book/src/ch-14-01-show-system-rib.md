# System, RIB and Forwarding

These commands report the daemon's identity, the contents of the
Routing Information Base (RIB), and the forwarding constructs the RIB
programs into the kernel — nexthop groups, MPLS labels, the L2 bridge
table, and SRv6 SIDs.

Every command honors the `-j` / `--json` flag described in the
[overview](ch-14-00-show-overview.md).

## Daemon identity

### `show version`

The package name and version, the git hash / branch / commit date the
binary was built from, and the build date. Answered by the management
task rather than a protocol daemon.

```
r1> show version
zebra-rs 0.1.0 (a3b4c5d / main, 2026-06-27)
```

JSON: an object with `package_name`, `package_version`, `git_hash`,
`git_branch`, `git_date`, `git_message`, `git_dirty`, and `build_date`.

### `show router-id`

The effective global Router ID and whether it was `configured`
explicitly or selected `automatic`ally from a loopback/interface
address. See [Router ID Selection](ch-00-01-router-id.md).

```
r1> show router-id
Router ID: 10.0.0.1 (configured)
```

JSON: `{ "routerId": "10.0.0.1", "source": "configured" }`, or
`{ "routerId": null }` when no Router ID has been selected yet.

### `show hostname`

The system hostname.

```
r1> show hostname
r1
```

JSON: `{ "hostname": "r1" }` (or `null` if unresolvable).

### `show task`

The protocol tasks the daemon has spawned and the VRF each runs in.
Useful for confirming a per-VRF protocol instance actually started.

```
r1> show task
Protocol  VRF
bgp       default
ospf      default
isis      blue
```

JSON: an array of `{ "protocol", "vrf" }` objects.

## VRFs and interfaces

### `show vrf`

Every VRF with its kernel table ID, per-VRF Router ID, and member
interfaces.

```
r1> show vrf
Name   Table-ID  Router-ID  Members
blue        100  10.1.1.1   eth1, eth2
red         200  10.2.2.1   eth3
```

JSON: `{ "vrfs": [ { "name", "table_id", "router_id", "members" } ] }`,
where `router_id` is `null` for a VRF with no Router ID yet.

### `show interface [brief | <name>]`

Interface state: hardware address, ifindex, MTU, flags, VRF binding,
MPLS switching state, and the IPv4/IPv6 addresses on the link.

- `show interface` — every interface, in detail (the default view).
- `show interface brief` — a one-line-per-interface summary table.
- `show interface <name>` — one interface, in detail.

```
r1> show interface brief
Interface  Status  VRF      Addresses
eth0       Up      default  10.0.0.1/24
eth1       Down    blue     -

r1> show interface eth0
Interface: eth0
  Hardware is Ethernet 00:11:22:33:44:55
  index 2 metric 1 mtu 1500
  Link is Up <UP,BROADCAST,RUNNING,MULTICAST>
  VRF Binding: Not bound
  inet 10.0.0.1/24
  inet6 2001:db8::1/64
```

JSON: an array of interface objects. The brief view carries `interface`,
`status`, `vrf`, and `addresses`; the detailed view adds `hardware`,
`index`, `metric`, `mtu`, `link_status`, `flags`, `vrf_binding`,
`label_switching`, `inet_addresses`, and `inet6_addresses`.

## IPv4 / IPv6 routing tables

The RIB views share a layout and a set of status/protocol codes. The
first column is the source protocol (`C` connected, `S` static,
`O` OSPF, `B` BGP, `L1`/`L2` IS-IS, `K` kernel, …); `*` marks the
FIB-installed route and `>` the selected best path.

### `show ip route` / `show ipv6 route`

The full IPv4 (resp. IPv6) routing table.

- `… detail` — IOS-XR-style routing-descriptor blocks: distance, metric,
  age, and per-nexthop detail (labels, weight, protection).
- `… prefix <A.B.C.D/M>` (`<X::Y/M>` for v6) `[detail]` — just the one
  prefix.
- `… vrf [<name>] [detail]` — the table for one VRF, or every VRF when
  `<name>` is omitted.

```
r1> show ip route
Codes: K - kernel, C - connected, S - static, O - OSPF,
       B - BGP, L1/L2 - IS-IS level-1/2,
       > - selected, * - FIB route

O   *> 10.0.0.0/24 [110/100] via 10.1.1.1, eth0, 00:12:34
C   *> 10.1.1.0/24 is directly connected, eth0, 00:05:43

r1> show ip route prefix 10.0.0.0/24 detail
Routing entry for 10.0.0.0/24
  Known via "ospf", distance 110, metric 100
  Last update 00:12:34 ago
  Routing Descriptor Blocks
    10.1.1.1, via eth0
      Route metric is 100, weight 0
```

JSON (all RIB forms): `{ "routes": [ … ] }`. Each route carries
`prefix`, `protocol`, `subtype`, `selected`, `fib`, `valid`, `distance`,
`metric`, `interface_name`, and a `nexthops` array whose entries hold
`address`, `interface`, `weight`, `metric`, `mpls_labels`, and `backup`.

> The per-VRF RIB forms (`show ip route vrf …`) are answered by the RIB
> directly, unlike the protocol per-VRF forms, which are redirected to a
> per-VRF task (see the [overview](ch-14-00-show-overview.md)).

## Forwarding constructs

### `show nexthop`

The nexthop groups the RIB has built. Each group shows its ID, refcount,
and `valid`/`installed` flags; single-path (`uni`), multipath (`multi`),
and protected (`protect`) groups render their members, weights, SRv6
segment lists, and MPLS label stacks.

```
r1> show nexthop
ID: 1 refcnt: 2 valid: true installed: true
  via 10.1.1.1, eth0, label 17003
ID: 2 refcnt: 1 valid: true installed: true
  [1] via 10.1.1.2, eth1, weight 1
  [3] via 10.1.1.3, eth2, weight 1
```

JSON: an array of group objects with `id`, `refcnt`, `valid`,
`installed`, and `type` (`uni` / `multi` / `protect`), plus either
inline `via`/`seg6`/`interface`/`labels` (uni) or a `members` array
(multi / protect). See [NexthopProtect](ch-12-00-nexthop-protect.md).

### `show mpls ilm`

The MPLS Incoming-Label Map: for each local label, the forwarding
action (`Pop`, `Swap <out>`, VPN decap), the prefix or SID it serves,
and the outgoing interface / nexthop.

```
r1> show mpls ilm
 P Dist Local  Outgoing  Prefix/ID          Interface  Next Hop
 * B  15   100  Pop       VPN Decap (tbl100) blue
   O 10   200  Swap 300  10.0.0.0/24        eth0       10.1.1.1
```

JSON: `{ "entries": [ { "protocol", "distance", "selected",
"local_label", "outgoing_label", "prefix_or_id", "outgoing_interface",
"next_hop" } ] }`.

### `show l2 mac table`

The EVPN MAC table — one entry per (VNI, MAC), with the remote VTEP
(tunnel endpoint), the entry flags, its sequence number, and whether it
is installed in the data plane. This is the control-plane view of the
MACs EVPN has learned, keyed by VNI.

```
r1> show l2 mac table
VNI    MAC Address        Tunnel Endpoint  Flags  Seq  Installed
5000   00:11:22:33:44:55  10.1.1.1         R      0    Yes
5001   aa:bb:cc:dd:ee:ff  10.2.2.1         R      2    Yes
```

JSON: `{ "entries": [ { "vni", "mac", "tunnel_endpoint", "flags",
"seq", "installed" } ] }`.

### `show l2 neighbor`

Bridge forwarding-database (FDB) entries — MACs learned locally or via
EVPN, with VLAN, VNI, remote VTEP, and state. Where
`show l2 mac table` is the per-VNI control-plane view, this is the
kernel-bridge FDB view.

```
r1> show l2 neighbor
 MAC                Interface  VLAN  VNI   Dst       State      Flags
 00:11:22:33:44:55  eth1       100   5000  10.1.1.1  Reachable  0x01
 aa:bb:cc:dd:ee:ff  eth2       200   5001  10.2.2.1  Stale      0x02
```

JSON: `{ "entries": [ { "mac", "interface", "vlan", "vni", "dst",
"state", "flags" } ] }`.

### `show segment-routing srv6 sid`

The SRv6 SIDs the daemon has allocated, with behavior (`End`, `End.X`,
`End.DT46`, …), context, owning protocol, locator, and allocation type.
Egress-protection redirects are shown beneath the affected SID. See
[SRv6](ch-04-00-srv6.md).

```
r1> show segment-routing srv6 sid
 SID              Behavior  Context             Protocol  Locator  AllocationType
 fcbb:bbbb:1:1::  End       -                   isis      LOC_N1   Dynamic
 fcbb:bbbb:1:2::  End.X     Interface 'enp0s7'  isis      LOC_N1   Dynamic
```

JSON: `{ "entries": [ { "sid", "behavior", "context", "owner",
"locator", "allocation_type", "redirected_to" } ] }`.

### `show evpn vni all`

A placeholder for EVPN VNI inventory. Per-VNI MAC state is surfaced by
`show l2 mac table`; this command currently returns an empty result
(text banner, or `[]` under `-j`) and is reserved for a future VNI
summary.
