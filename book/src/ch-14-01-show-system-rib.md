# System, RIB and Forwarding

These commands report the daemon's identity, its VRFs and interfaces,
the L2 bridge table, and SRv6 SIDs. The routing tables, nexthop groups
and MPLS labels are in [Routing Table (RIB)](ch-18-00-rib.md).

Every command honors the `-j` / `--json` flag described in the
[overview](ch-06-03-show-commands.md).

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
MPLS switching state, and the IPv4/IPv6 addresses on the link. An
802.1Q sub-interface — whether created from the
[`vlan`](ch-00-08-vlan-configuration.md) list or learned from the
kernel — additionally reports its tag and parent device.

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

r1> show interface eth0.100
Interface: eth0.100
  Hardware is Ethernet 00:11:22:33:44:55
  index 12 metric 1 mtu 1500
  VLAN id 100 parent eth0 (index 2)
  Link is Up <UP,BROADCAST,RUNNING,MULTICAST>
  ...
```

JSON: an array of interface objects. The brief view carries `interface`,
`status`, `vrf`, and `addresses`; the detailed view adds `hardware`,
`index`, `metric`, `mtu`, `link_status`, `flags`, `vrf_binding`,
`label_switching`, `inet_addresses`, and `inet6_addresses`. A VLAN
sub-interface also carries `vlan_id`, `parent` (the parent's name), and
`parent_index`; the fields are omitted on ordinary interfaces.

## Routing tables, nexthops and MPLS

`show ip route`, `show ipv6 route`, `show nexthop`, `show mpls ilm` and
`show mpls label range|table` are in
[Routing Table (RIB)](ch-18-00-rib.md).

## Forwarding constructs

### `show l2 mac table`

The EVPN MAC table — one entry per (VNI, MAC), with the overlay
destination the MAC sits behind, the entry flags, its sequence number,
and whether it is installed in the data plane. This is the
control-plane view of the MACs EVPN has learned, keyed by VNI.

The destination depends on the encapsulation the route arrived with:
the remote VTEP for EVPN-over-VXLAN, or the remote PE's `End.DT2U`
service SID for EVPN-over-SRv6 (RFC 9252). `Encap` states which — an
IPv6 destination alone is ambiguous, since VXLAN also runs over an IPv6
underlay. A locally-learned MAC has neither and shows `-`.

```
r1> show l2 mac table
VNI    MAC Address         Encap Tunnel Endpoint       Flags Seq    Installed
5000   00:11:22:33:44:55   vxlan 10.1.1.1              R     0      Yes
5001   aa:bb:cc:dd:ee:ff   vxlan 10.2.2.1              R     2      Yes
10     02:00:00:00:00:02   srv6  fcbb:bbbb:2:e000::    R     0      Yes
```

JSON: `{ "entries": [ { "vni", "mac", "tunnel_endpoint", "encap",
"flags", "seq", "installed" } ] }`.

For one line per VNI instead of per MAC, use
[`show evpn vni all`](ch-02-48-bgp-show.md#show-evpn-vni-all).

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
