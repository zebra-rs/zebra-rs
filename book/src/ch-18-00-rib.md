# Routing Table (RIB)

The Routing Information Base (RIB) holds every route zebra-rs knows. It
takes them from every source: connected networks, static routes, routes
found in the kernel, and the routes the routing protocols compute. For
each prefix the RIB selects one route and installs it in the kernel's
forwarding table (FIB). It also builds the nexthop groups the installed
routes share, and the MPLS label table the protocols' labels fill.

This chapter covers the commands that show them. Every command honors
`-j` / `--json`; see
[Operational Show Commands](ch-06-03-show-commands.md) for how to run a
show command and request JSON.

## Route selection

A prefix can have one entry per source. Among its valid entries, the RIB
selects the one with the lowest administrative distance, then the lowest
metric, then by source. The selected entry is the one installed in the
FIB.

Each source sets the distance of its routes:

| Source | Distance |
|---|---|
| Connected, kernel | 0 |
| Static | 1, unless configured (see [Floating Static Route](ch-01-01-floating-static-route.md)) |
| BGP | 20 for eBGP, 200 for iBGP and locally originated routes |
| OSPF | 110 |
| IS-IS | 115 |

A connected network that a routing protocol also runs on therefore has
two entries: the connected one is selected, and the protocol's is kept
but not installed.

## The examples

The examples come from r1 in the four-router network of the
[OSPFv2](ch-08-18-ospf-show.md) and [OSPFv3](ch-15-18-ospfv3-show.md)
show pages. It runs OSPFv2 and OSPFv3 with SR-MPLS (Prefix-SID index
*n* and Flexible Algorithm 128 index 100+*n* on r*n*'s loopback for
OSPFv2, 20+*n* and 120+*n* for OSPFv3), TI-LFA and Flexible Algorithm
128:

```
        10          10 (LAN)
   r1 ------- r2 ------------ r4 --- area 0.0.0.1
    \         |              /       (172.16.4.0/24)
  15 \     10 |             / 30
      \       |            /
       ------ r3 ----------
```

r1 also has a static route, 198.51.100.0/24 via r2 (192.168.12.2), and
a second link to r2, r1-v (192.168.120.0/24), in VRF `blue`, where a
second OSPFv2 instance runs.

## IPv4 and IPv6 routes

### `show ip route` / `show ipv6 route`

The whole IPv4 (or IPv6) table of the default VRF, one line per entry:

```
r1> show ip route
Codes: K - kernel, D - DHCP route, C - connected, S - static
       O - OSPF, IA - OSPF inter area, N1/N2 - OSPF NSSA external type 1/2
       E1/E2 - OSPF external type 1/2
       L1/L2 - IS-IS level-1/2, B - BGP
       > - selected route, * - FIB route, ? - backup route

C  *> 10.0.0.1/32 is directly connected, lo, 00:01:10
O  *> 10.0.0.2/32 [110/10] via 192.168.12.2, r1-r2, label 16002, 00:00:51
O  *> 10.0.0.3/32 [110/15] via 192.168.13.3, r1-r3, label 16003, 00:00:51
O  *> 10.0.0.4/32 [110/20] via 192.168.12.2, r1-r2, label 16004, 00:00:29
   *?             [110/21] via 192.168.13.3, r1-r3, label 16003 15002 16004, 00:00:29
C  *> 127.0.0.0/8 is directly connected, lo, 00:01:13
C  *> 172.16.1.0/24 is directly connected, d1, 00:01:10
O  *> 172.16.4.0/24 [110/30] via 192.168.12.2, r1-r2, 00:00:29
   *?               [110/31] via 192.168.13.3, r1-r3, label 16003 15002, 00:00:29
C  *> 192.168.12.0/24 is directly connected, r1-r2, 00:01:10
C  *> 192.168.13.0/24 is directly connected, r1-r3, 00:01:10
O  *> 192.168.23.0/24 [110/20] via 192.168.12.2, r1-r2, 00:00:51
O  *> 192.168.24.0/24 [110/20] via 192.168.12.2, r1-r2, 00:00:51
O  *> 192.168.34.0/24 [110/45] via 192.168.13.3, r1-r3, 00:00:51
S  *> 198.51.100.0/24 [1/0] via 192.168.12.2, r1-r2, 00:00:05
```

Each line holds:

1. **The source code:** `C` connected, `S` static, `K` kernel, `O`
   OSPF, `B` BGP, `D` DHCP. An OSPF route that is not intra-area shows
   its route type instead: `IA` inter-area, `E1`/`E2` external,
   `N1`/`N2` NSSA external. An IS-IS route shows its level, `L1` or
   `L2`.
2. **Two markers:** `*` the entry is in the FIB, `>` it is the selected
   entry.
3. **The prefix**, then `[distance/metric]`. A connected route has
   neither and reads `is directly connected, <interface>`.
4. **The nexthop:** `via <address>, <interface>`. A route with no
   gateway reads `via <interface>`, a discard route
   `is a discard (blackhole)`, and an SRv6 nexthop
   `via seg6 [<segments>]`.
5. **The label stack** pushed onto the packet, if any: `label 16003
   15002 16004`, the outermost first.
6. **The age** of the entry (`hh:mm:ss`, or `1d2h3m` from a day on), and
   `offloaded` when the forwarding plane has acknowledged the route.

A route with more than one path prints the others on the lines below,
under its own columns:

- **A TI-LFA backup path** is marked `?` in place of `>`, with its own
  `[distance/metric]` and the label stack of its repair path. In the
  example, 10.0.0.4/32 goes through r2, and its backup through r3.
- **An ECMP path** follows with `, weight <n>` before its age; every
  path of an ECMP route carries its weight.
- **A recursive static route** prints its configured gateway, tagged
  `(recursive)`, then the nexthop it resolved to.

OSPFv3's nexthops are its neighbors' link-local addresses:

```
r1> show ipv6 route
Codes: K - kernel, D - DHCP route, C - connected, S - static
       O - OSPF, IA - OSPF inter area, N1/N2 - OSPF NSSA external type 1/2
       E1/E2 - OSPF external type 1/2
       L1/L2 - IS-IS level-1/2, B - BGP
       > - selected route, * - FIB route, ? - backup route

C  *> ::1/128 is directly connected, lo, 00:01:13
C  *> 2001:db8::1/128 is directly connected, lo, 00:01:10
O  *> 2001:db8::2/128 [110/10] via fe80::dcc8:f3ff:feaf:eb3d, r1-r2, label 16022, 00:00:51
O  *> 2001:db8::3/128 [110/15] via fe80::f8b9:b7ff:fedc:fbc1, r1-r3, label 16023, 00:00:51
O  *> 2001:db8::4/128 [110/20] via fe80::dcc8:f3ff:feaf:eb3d, r1-r2, label 16024, 00:00:30
   *?                 [110/21] via fe80::f8b9:b7ff:fedc:fbc1, r1-r3, label 16023 15003 16024, 00:00:30
C  *> 2001:db8:12::/64 is directly connected, r1-r2, 00:01:10
C  *> 2001:db8:13::/64 is directly connected, r1-r3, 00:01:10
O  *> 2001:db8:23::/64 [110/20] via fe80::dcc8:f3ff:feaf:eb3d, r1-r2, 00:00:51
O  *> 2001:db8:24::/64 [110/20] via fe80::dcc8:f3ff:feaf:eb3d, r1-r2, 00:00:30
   *?                  [110/21] via fe80::f8b9:b7ff:fedc:fbc1, r1-r3, label 16023 15003, 00:00:30
O  *> 2001:db8:34::/64 [110/45] via fe80::f8b9:b7ff:fedc:fbc1, r1-r3, 00:00:51
C  *> 2001:db8:f1::/64 is directly connected, d1, 00:01:10
O  *> 2001:db8:f4::/64 [110/30] via fe80::dcc8:f3ff:feaf:eb3d, r1-r2, 00:00:30
   *?                  [110/31] via fe80::f8b9:b7ff:fedc:fbc1, r1-r3, label 16023 15003, 00:00:30
C  *> fe80::/64 is directly connected, r1-r2, 00:01:13
C  *> fe80::/64 is directly connected, r1-r3, 00:01:13
C  *> fe80::/64 is directly connected, d1, 00:01:13
C  *> fe80::/64 is directly connected, sr0, 00:01:13
```

### `show ip route <address>` / `show ip route <prefix>`

One route, with the same layout. An address (`<A.B.C.D>`) shows the
longest match, the route that covers it. A prefix (`<A.B.C.D/M>`) shows
that entry exactly. IPv6 takes `<X:X::X:X>` and `<X:X::X:X/M>`.

```
r1> show ip route 10.0.0.4
Codes: K - kernel, D - DHCP route, C - connected, S - static
       O - OSPF, IA - OSPF inter area, N1/N2 - OSPF NSSA external type 1/2
       E1/E2 - OSPF external type 1/2
       L1/L2 - IS-IS level-1/2, B - BGP
       > - selected route, * - FIB route, ? - backup route

O  *> 10.0.0.4/32 [110/20] via 192.168.12.2, r1-r2, label 16004, 00:00:30
   *?             [110/21] via 192.168.13.3, r1-r3, label 16003 15002 16004, 00:00:30
```

With no route, the answer is `% No route for <address or prefix>`.

### `show ip route detail` / `show ipv6 route detail`

One block per entry:

- **`Known via`:** the source, the distance and the metric. `labeled SR`
  follows when a path pushes labels, and the route type (`type
  inter-area`, `type external type 2`, `type level-2`, …) for an OSPF or
  IS-IS route that has one. `show ipv6 route detail` also adds `SRv6`
  when a path carries a segment list.
- **`Last update`:** the age of the entry.
- **`Offloaded to the forwarding plane`**, when the forwarding plane has
  acknowledged the route.
- **`Directly connected via <interface>`** for a connected route.
- **`Routing Descriptor Blocks`** for any other route: one block per
  path, naming its nexthop and interface. A protected path is tagged
  `Protected` and its TI-LFA backup `Backup (TI-LFA)`; a path with no
  backup has no tag. Below each: its metric and weight, the labels it
  pushes (`Labels imposed`), and for a backup, the first of those labels,
  the Node-SID of the node the repair path goes through
  (`Repair Node(s)`).

```
r1> show ip route detail
...
Routing entry for 10.0.0.2/32
  Known via "ospf", distance 110, metric 10, labeled SR
  Last update 00:00:51 ago
  Routing Descriptor Blocks
    192.168.12.2, via r1-r2
      Route metric is 10, weight 1
      Labels imposed { 16002 }
...
Routing entry for 10.0.0.4/32
  Known via "ospf", distance 110, metric 20, labeled SR
  Last update 00:00:30 ago
  Routing Descriptor Blocks
    192.168.12.2, via r1-r2, Protected
      Route metric is 20, weight 1
      Labels imposed { 16004 }
    192.168.13.3, via r1-r3, Backup (TI-LFA)
      Route metric is 21, weight 1
      Labels imposed { 16003 15002 16004 }
      Repair Node(s): label 16003
...
Routing entry for 172.16.1.0/24
  Known via "connected", distance 0, metric 0
  Last update 00:01:10 ago
  Directly connected via d1
...
Routing entry for 198.51.100.0/24
  Known via "static", distance 1, metric 0
  Last update 00:00:05 ago
  Routing Descriptor Blocks
    192.168.12.2, via r1-r2
      Route metric is 0, weight 1
```

`show ip route detail` takes no address or prefix; the one-line view
does.

### `show ip route vrf [<name>]`

The table of one VRF, or of every VRF when the name is left out, each
under a `VRF <name> (table <id>):` heading. `show ip route vrf <name>
detail` prints the blocks, and `show ip route vrf <name> <address>` (or
`<prefix>`) one route. `show ipv6 route vrf` is the IPv6 twin.

```
r1> show ip route vrf blue
VRF blue (table 1):
Codes: K - kernel, D - DHCP route, C - connected, S - static
       O - OSPF, IA - OSPF inter area, N1/N2 - OSPF NSSA external type 1/2
       E1/E2 - OSPF external type 1/2
       L1/L2 - IS-IS level-1/2, B - BGP
       > - selected route, * - FIB route, ? - backup route

C  *> 192.168.120.0/24 is directly connected, r1-v, 00:01:10
O     192.168.120.0/24 [110/10] via 0.0.0.0, r1-v, 00:01:04
```

192.168.120.0/24 has two entries: the connected route, selected, and the
route of OSPF running on that link, not installed.

The RIB answers these itself, from its per-VRF tables. They are not
replayed against a per-VRF task, unlike the protocols' per-VRF forms
(see [Per-VRF forms](ch-06-03-show-commands.md#per-vrf-forms)).

### JSON

Every form returns `{ "routes": [ … ] }`, with one object per entry:

- `prefix`, `protocol` (`connected`, `static`, `kernel`, `ospf`, `isis`,
  `bgp`, `dhcp`) and `subtype` (`default`, or the route type, such as
  `ospfia`, `ospfexternal2` or `level2`);
- `selected`, `fib` and `valid`;
- `distance` and `metric`;
- `interface_name`, a connected route's interface, `null` for others;
- `vrf`, the route's VRF, in the `vrf` forms only;
- `nexthops`: one object per path, with `address` (`null` for a route
  with no gateway), `interface`, `weight`, `metric`, `mpls_labels` (a
  list of `{ "label": <n> }`) and, on a backup path, `"backup": true`.

```
$ vtyctl show -j 'show ip route 10.0.0.4/32'
{
  "routes": [
    {
      "prefix": "10.0.0.4/32",
      "protocol": "ospf",
      "subtype": "default",
      "selected": true,
      "fib": true,
      "valid": true,
      "distance": 110,
      "metric": 20,
      "nexthops": [
        {
          "address": "192.168.12.2",
          "interface": "r1-r2",
          "weight": 1,
          "metric": 20,
          "mpls_labels": [
            {
              "label": 16004
            }
          ]
        },
        {
          "address": "192.168.13.3",
          "interface": "r1-r3",
          "weight": 1,
          "metric": 21,
          "mpls_labels": [
            {
              "label": 16003
            },
            {
              "label": 15002
            },
            {
              "label": 16004
            }
          ],
          "backup": true
        }
      ],
      "interface_name": null
    }
  ]
}
```

The detail forms return the same JSON as their one-line forms. With no
VRF name, `show ip route vrf` returns the routes of every VRF in one
list, without the VRF's name.

## Forwarding

### `show nexthop`

The nexthop groups the RIB has built for the kernel. Routes with the
same path share one group. Each group shows its ID, its reference count
(`refcnt`), whether it resolves (`valid`) and whether the kernel holds it
(`installed`). Then:

- **A single path:** `via <address>, <interface>`, and the label stack
  it pushes, as `label <n> …`. An SRv6 path reads
  `via seg6 [<segments>]`.
- **An ECMP group:** one `[<id>] via <address>, <interface>, weight: <n>`
  line per member group.
- **A protected group:** its `primary` and `backup` member groups. The
  `*` marks the one the kernel group holds now; a TI-LFA switchover
  moves it to the backup.

```
r1> show nexthop
...
ID: 8 refcnt: 4 valid: true installed: true
  via 192.168.12.2, r1-r2
...
ID: 19 refcnt: 1 valid: true installed: true
  via 192.168.12.2, r1-r2, label 16004
ID: 20 refcnt: 1 valid: true installed: true
  via 192.168.13.3, r1-r3, label 16003 15002 16004
ID: 21 refcnt: 1 valid: true installed: true
 *primary [19] via 192.168.12.2, r1-r2
  backup [20] via 192.168.13.3, r1-r3
ID: 22 refcnt: 1 valid: true installed: true
  via 192.168.13.3, r1-r3, label 16003 15002
ID: 23 refcnt: 1 valid: true installed: true
 *primary [8] via 192.168.12.2, r1-r2
  backup [22] via 192.168.13.3, r1-r3
```

Group 21 is 10.0.0.4/32's: group 19, the path through r2, and group 20,
the TI-LFA repair path through r3. Group 8, a plain path through r2, is
shared: its `refcnt` is 4. Group 23, 172.16.4.0/24's protected group,
uses it as its primary.

JSON: a list of groups, each with `id`, `refcnt`, `valid`, `installed`
and `type` (`uni`, `multi` or `protect`). A `uni` group adds `via` (or
`seg6`, a segment list), `interface` and `labels`. A `multi` or
`protect` group adds `members`, each with `id`, `via` (or `seg6`) and
`interface`, plus `weight` in a `multi` group, and `role` (`primary` or
`backup`) and `"active": true` (on the member the kernel holds) in a
`protect` group. See [Fast Failover](ch-12-00-nexthop-protect.md).

### `show mpls ilm`

The MPLS Incoming Label Map: what the node does with a packet that
arrives with each local label. One line per entry, with:

- **`P`:** `*>` for the selected entry, or `S` for a leftover from an
  earlier run; then the source code.
- **`Dist`:** the distance.
- **`Local Label`.**
- **`Outgoing Label`:** the label swapped in, `Pop` when the label is
  removed, or `Aggregate` for a label that decapsulates into a table.
- **`Prefix or ID`:** what the label stands for:
  - `SR Pfx (idx <n>)`, a Prefix-SID;
  - `SR Adj (idx <n>)`, an Adjacency-SID, indexed within the SRLB;
  - `VPN Decap (tbl <id>)`, a VPN label into a VRF's table;
  - `Mirror Ctx (tbl <id>)`, a Mirror SID's context label;
  - `EVPN Decap (bd <id>)`, an EVPN label into a bridge domain;
  - `LU Swap`, a BGP labeled-unicast label;
  - `Earlier run`, a leftover;
  - `-`, a static label binding.
- **`Outgoing Interface` and `Next Hop`.**

```
r1> show mpls ilm
   P Dist Local  Outgoing    Prefix             Outgoing     Next Hop
          Label  Label       or ID              Interface
-- - ---- ------ ----------- ------------------ ------------ ---------------
*> O 110  15000  Pop         SR Adj (idx 0  )   r1-r3        192.168.13.3
*> O 110  15001  Pop         SR Adj (idx 1  )   r1-r2        192.168.12.2
*> O 110  15002  Pop         SR Adj (idx 2  )   r1-r2        fe80::dcc8:f3ff:feaf:eb3d
*> O 110  15003  Pop         SR Adj (idx 3  )   r1-r3        fe80::f8b9:b7ff:fedc:fbc1
*> O 110  16001  Pop         SR Pfx (idx 1  )   lo           127.0.0.1
*> O 110  16002  16002       SR Pfx (idx 2  )   r1-r2        192.168.12.2
*> O 110  16003  16003       SR Pfx (idx 3  )   r1-r3        192.168.13.3
*> O 110  16004  16004       SR Pfx (idx 4  )   r1-r2        192.168.12.2
*> O 110  16021  Pop         SR Pfx (idx 21 )   lo           ::1
*> O 110  16022  16022       SR Pfx (idx 22 )   r1-r2        fe80::dcc8:f3ff:feaf:eb3d
*> O 110  16023  16023       SR Pfx (idx 23 )   r1-r3        fe80::f8b9:b7ff:fedc:fbc1
*> O 110  16024  16024       SR Pfx (idx 24 )   r1-r2        fe80::dcc8:f3ff:feaf:eb3d
*> O 110  16101  Pop         SR Pfx (idx 101)   lo           127.0.0.1
*> O 110  16102  16102       SR Pfx (idx 102)   r1-r2        192.168.12.2
*> O 110  16103  16103       SR Pfx (idx 103)   r1-r3        192.168.13.3
*> O 110  16104  16104       SR Pfx (idx 104)   r1-r2        192.168.12.2
*> O 110  16121  Pop         SR Pfx (idx 121)   lo           ::1
*> O 110  16122  16122       SR Pfx (idx 122)   r1-r2        fe80::dcc8:f3ff:feaf:eb3d
*> O 110  16123  16123       SR Pfx (idx 123)   r1-r3        fe80::f8b9:b7ff:fedc:fbc1
*> O 110  16124  16124       SR Pfx (idx 124)   r1-r2        fe80::dcc8:f3ff:feaf:eb3d
```

r1 swaps another router's Prefix-SID label to the same label toward it,
even as the last hop before that router: zebra-rs sets the NP flag on
the index Prefix-SIDs it originates, which asks that hop to keep the
label. r1 pops its own Prefix-SIDs, for algorithm 0 (16001, 16021) and
for Flexible Algorithm 128 (16101, 16121), and its Adjacency-SIDs, 15000
to 15003.

JSON: `{ "entries": [ … ] }`, each with `protocol`, `distance`,
`selected`, `local_label`, `outgoing_label`, `prefix_or_id`,
`outgoing_interface` and `next_hop`, plus `"stale": true` on a leftover.

### `show mpls label range`

The regions of the node's MPLS label space, in order, and how many labels
are allocated in each. The reserved labels come first. Then each
`segment-routing block`'s SRGB and SRLB, and an SRGB still held while
Prefix-SID labels move off it after a change. The dynamic range, where
label blocks are handed out, starts at 24000 unless `mpls label-range
dynamic` moves it. Static is whatever those leave. A block handed out
before the range moved stays where it is until released, and is counted
in the region it now falls in.

```
r1> show mpls label range
Range            Region                                   Allocated
0-15             reserved (RFC 3032, RFC 7274)
16-14999         static
15000-15999      SRLB of segment-routing block default    4 labels
16000-23999      SRGB of segment-routing block default
24000-1048574    dynamic
```

Allocated counts what the label space hands out: label blocks (BGP's)
and IGP local labels. Static bindings and Prefix-SID labels are
configuration, not allocations; `show mpls ilm` shows them.

JSON: `{ "regions": [ { "first", "last", "region", "kind", "block",
"allocated_labels", "allocated_blocks" } ] }`, where `kind` is
`reserved`, `static`, `srgb`, `srlb`, `retired-srgb` or `dynamic`.

### `show mpls label table [label <n>]`

Everything the label space has handed out, by first label, with its
owner, kind and state:

- **Kind:** `block` is a label block for a protocol that allocates its
  own labels. `local` is an IGP instance's label for a dynamic SID (an
  Adjacency-SID, a Mirror Context label). `configured SID` is a label
  claimed for a configured absolute Adjacency-SID.
- **State:** `held` and `claimed` are in use. A label given back is
  `releasing` until the RIB is past its owner's earlier messages, then
  `draining` until the owner's ILM entry at it is withdrawn, and only
  then free. `claimed by <protocol>` means a configured SID is waiting
  for the label.

```
r1> show mpls label table
Label          Owner   Kind            State
15000          ospf    local           held
15001          ospf    local           held
15002          ospfv3  local           held
15003          ospfv3  local           held
```

r1's four Adjacency-SID labels: OSPFv2's two and OSPFv3's two, all from
the SRLB.

`label <n>` shows one label: the region it is in, and what holds it.

```
r1> show mpls label table label 15000
Label 15000: SRLB of segment-routing block default
Label          Owner   Kind            State
15000          ospf    local           held

r1> show mpls label table label 16004
Label 16004: SRGB of segment-routing block default
  not allocated (Prefix-SID labels: see show mpls ilm)
```

JSON: `{ "entries": [ { "first", "last", "owner", "kind", "state",
"claimed_by" } ] }`; with `label <n>`, `{ "label", "regions", "entries" }`.
