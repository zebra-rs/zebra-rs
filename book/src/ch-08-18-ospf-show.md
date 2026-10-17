# OSPFv2 Show Commands

The `show ospf` family reports the instance summary, interfaces and
neighbors, the link-state database, the computed routes, SPF tree and
graph, Segment Routing, Flexible Algorithm, TI-LFA and Graceful Restart
state. Every command honors `-j` / `--json`; see
[Operational Show Commands](ch-06-03-show-commands.md) for how to run a
show command and request JSON. See [OSPFv2](ch-08-00-ospf.md) for the
configuration, and [OSPFv3 Show Commands](ch-15-18-ospfv3-show.md) for
the `show ospfv3` family.

`show ospf vrf <name>` runs the summary, `interface`, `neighbor [detail]`,
`database [detail]` or `route` against that VRF's OSPFv2 instance, with
the same output as the default-VRF command. The other commands have no
per-VRF spelling.

The examples come from a four-router network running SR-MPLS
(Prefix-SID index *n* and Flexible Algorithm 128 index 100+*n* on r*n*'s
loopback), TI-LFA and Flexible Algorithm 128:

```
        10          10 (LAN)
   r1 ------- r2 ------------ r4 --- area 0.0.0.1
    \         |              /       (172.16.4.0/24)
  15 \     10 |             / 30
      \       |            /
       ------ r3 ----------
```

Everything except 172.16.4.0/24 is in area 0.0.0.0. r1–r2, r1–r3, r2–r3
and r3–r4 are point-to-point links; r2–r4 is a broadcast network with r4
as its DR. r4 is an ABR: 172.16.4.0/24 is a passive interface in area
0.0.0.1. r1 redistributes the connected network 172.16.1.0/24.

## Overview

### `show ospf`

The instance summary: Router ID, when the last SPF ran and how long it
took, the SPF throttle timers, the LSA rate limits, the TI-LFA
computation of the last SPF (only when TI-LFA is configured), and for
each area whether an SPF is running or queued.

```
r1> show ospf
 OSPF Routing Process, Router ID: 10.0.0.1
 SPF algorithm last executed 0m34s ago
 Last SPF duration 133 usecs
 SPF timers: initial 50 ms, secondary 200 ms, maximum 5000 ms
 MinLSInterval (self-LSA re-origination): 5000 ms
 MinLSArrival (received-LSA rate limit): 1000 ms
 TI-LFA compute: targets=3 mode=serial workers=1 spf{q=3 pc=3 dedup-saved=0} took 79 usecs
 SPF offload gates:
   area 0.0.0.0: inflight=false, pending=false
```

JSON: `{ router_id, area_count, link_count, spf_last_ms_ago,
spf_duration_us, tilfa_compute, spf_offload_gates: [ { area_id,
spf_inflight, spf_pending } ] }`. `link_count` counts every interface
the instance tracks, OSPF-enabled or not. `tilfa_compute` is the TI-LFA
line as a string, or `null` without TI-LFA.

## Interfaces and neighbors

### `show ospf interface`

One block per OSPF-enabled interface: its state, ifindex, MTU and flags;
primary address, broadcast address and area; whether MTU mismatch
detection is on; Router ID, network type and cost; transmit delay,
interface state (`DR`, `Backup`, `DROther`, `Point-To-Point`, `Waiting`,
…) and priority; the multicast groups joined; the Hello, Dead, Wait and
Retransmit intervals with the time to the next Hello (or
`No Hellos (Passive interface)`); the neighbor and adjacency counts; the
graceful-restart Hello delay; and the number of LSA retransmissions.

```
r1> show ospf interface
...
r1-r2 is up
  ifindex 2, MTU 1500 bytes, BW 0 Mbit <UP,LOWER_UP,BROADCAST,RUNNING,MULTICAST>
  Internet Address 192.168.12.1/24, Broadcast 192.168.12.255, Area 0.0.0.0
  MTU mismatch detection: enabled
  Router ID 10.0.0.1, Network Type POINT-TO-POINT, Cost: 10
  Transmit Delay is 1 sec, State Point-To-Point, Priority 64
  Multicast group memberships: OSPFAllRouters
  Timer intervals configured, Hello 10s, Dead 40s, Wait 40s, Retransmit 5
    Hello due in 5.057s
  Neighbor Count is 1, Adjacent neighbor count is 1
  Graceful Restart hello delay: 10s
  LSA retransmissions: 0
...
```

On a broadcast network the block also names the
`Designated Router (ID)` and `Backup Designated Router (ID)` with their
interface addresses, and the DR shows the sequence number of the
Network-LSA it originates.

JSON: an array of `{ name, status, ifindex, mtu, address, broadcast,
area, router_id, network_type, cost, transmit_delay, state, priority,
hello_interval, dead_interval, retransmit_interval, hello_due,
neighbor_count, adjacent_count }`, plus `dr_id` / `dr_address` and
`bdr_id` / `bdr_address` when a DR or BDR is known.

### `show ospf neighbor [detail]`

The neighbor table. `State` is the neighbor state machine state and,
after the slash, the neighbor's role on the link (`DR`, `Backup` or
`DROther`; point-to-point neighbors read `DROther`). `Dead Time` is the
time left on the inactivity timer, `Interface` is the local interface
and address, and `RXmtL`, `RqstL` and `DBsmL` are the sizes of the
retransmission, link-state request and database summary lists.

```
r2> show ospf neighbor
Neighbor ID     Pri State                   Up Time  Dead Time Address         Interface                        RXmtL RqstL DBsmL
10.0.0.1         64 Full/DROther              1m05s    34.512s 192.168.12.1    r2-r1:192.168.12.2                   0     0     0
10.0.0.3         64 Full/DROther              1m15s    34.587s 192.168.23.3    r2-r3:192.168.23.2                   0     0     0
10.0.0.4         64 Full/DR                   1m15s    34.617s 192.168.24.4    r2-r4:192.168.24.2                   0     0     0
```

`detail` gives one block per neighbor: its interface address, area and
local interface; priority, state, role and the number of state changes;
how long ago its state last progressed; the DR and BDR of the link as
this router sees them; the options it advertised; the inactivity timer;
and the three list sizes.

```
r2> show ospf neighbor detail
 Neighbor 10.0.0.1, interface address 192.168.12.1
    In the area 0.0.0.0 via interface r2-r1 local interface IP 192.168.12.2
    Neighbor priority is 64, State is Full/DROther, Role is DROther, 5 state changes
    0 LSA retransmissions
    Most recent state change statistics:
      Progressive change 1m05s ago
    DR is 0.0.0.0, BDR is 0.0.0.0
    Options 66 *|O|-|-|-|-|E|-
    Dead timer due in 34.496s
    Database Summary List 0
    Link State Request List 0
    Link State Retransmission List 0
...
```

JSON: an array of `{ neighbor_id, priority, state, up_time, dead_time,
address, interface, retransmit_list, request_list, db_summary_list }`.
`detail` returns `{ neighbor_id, interface_address, area, interface,
local_interface_ip, priority, state, role, state_changes,
lsa_retransmissions, last_progressive_change, dr, bdr, options,
dead_timer, db_summary_list, ls_request_list, ls_retransmission_list }`.

## Link-state database

### `show ospf database [detail]`

The backbone area's Router, Network and area-scope Opaque LSAs (Router
Information, Extended Prefix and Extended Link). Each row gives the
Link-State ID, advertising router, age, sequence number and checksum.
`Hold` is the time left before the LSA reaches MaxAge; for this router's
own LSAs the time to the next refresh follows in parentheses. Opaque
LSAs are listed by `type.id`, for example `7.0.0.1` for Extended Prefix
LSA 1.

```
r1> show ospf database
       OSPF Router with ID (10.0.0.1)

Router Link States (Area 0.0.0.0)

Link ID         ADV Router      Age  Seq#       CkSum  Link count  Hold
10.0.0.1        10.0.0.1          59 0x80000004 0x9c31          5  3540s (1740s)
10.0.0.2        10.0.0.2          35 0x80000005 0x831b          6  3564s
10.0.0.3        10.0.0.3          59 0x80000004 0xd559          7  3540s
10.0.0.4        10.0.0.4          36 0x80000004 0x4838          4  3563s

Net Link States (Area 0.0.0.0)

Link ID         ADV Router      Age  Seq#       CkSum   Hold
192.168.24.4    10.0.0.4          36 0x80000001 0x4b63  3563s

                Area-Local Opaque-LSA (Area 0.0.0.0)

Opaque-Type/Id  ADV Router      Age  Seq#       CkSum   Hold
4.0.0.0         10.0.0.1          74 0x80000003 0x9637  3525s (1725s)
4.0.0.0         10.0.0.2          74 0x80000003 0x903c  3525s
...
```

The view covers area 0.0.0.0 only, and only these three LSA types.
Summary, ASBR-summary, AS-external and NSSA LSAs, and the LSAs of other
areas, are not displayed; `show ospf route` lists the routes they
produce.

`detail` decodes every LSA: the header fields, then the body — each
Router-LSA link with its type, Link ID, Link Data and metric; each
Network-LSA's mask and attached routers; and each Opaque LSA's TLVs.

```
r1> show ospf database detail
       OSPF Router with ID (10.0.0.1)

                Router Link States (Area 0.0.0.0)

  LS age: 59
  Options: 0x0  : *|-|-|-|-|-|-|-
  LS Type: Router Links
  Link State ID: 10.0.0.1
  Advertising Router: 10.0.0.1
  LS Seq Number: 0x80000004
  Checksum: 0x9c31
  Length: 84
  Hold remaining: 3540s
  Refresh remaining: 1740s
  Number of Links: 5

    Link connected to: Stub Network
     (Link ID) Network/subnet number: 10.0.0.1
     (Link Data) Network Mask: 255.255.255.255
      Number of TOS metrics: 0
       TOS 0 Metric: 0

    Link connected to: Point-to-Point
     (Link ID) Neighboring Router ID: 10.0.0.2
     (Link Data) Router Interface address: 192.168.12.1
      Number of TOS metrics: 0
       TOS 0 Metric: 10
...
  LS age: 74
  Options: 0x42  : *|O|-|-|-|-|E|-
  LS Type: Area-Local Opaque-LSA (Opaque Type 7)
  Opaque-Type 7 (Extended Prefix LSA)
  Opaque-ID   0x1
  Advertising Router: 10.0.0.1
  LS Seq Number: 0x80000003
  Checksum: 0x9b80
  Length: 56
  Hold remaining: 3525s
  Refresh remaining: 1725s
  Opaque-Info: 36 octets of data
  Extended Prefix TLV: Route Type: 1 (Intra-Area)
    Prefix: 10.0.0.1/32
    AF: 0
    Flags: 0x00
    Prefix SID Sub-TLV:
      Algorithm: SPF(0)
      SID/Label: Index: 1
      Flags: 0x40
      MT-ID: 0
    Prefix SID Sub-TLV:
      Algorithm: FlexAlgo(128)
      SID/Label: Index: 101
      Flags: 0x40
      MT-ID: 0
...
```

JSON: `{ router_id, areas: [ { area_id, router_lsas, network_lsas,
opaque_area_lsas } ] }`, each LSA `{ link_id, adv_router, age,
seq_number, checksum }` and Router-LSAs also `link_count`. `detail`
returns `router_lsas` (`{ ls_age, options, link_state_id,
advertising_router, ls_seq_number, checksum, length, num_links, links:
[ { link_type, link_id, link_data, num_tos, tos_0_metric } ] }`) and
`network_lsas` (the same header plus `network_mask` and
`attached_routers`); the Opaque LSAs are in the text form only.

## Routes, SPF and graph

### `show ospf route`

The routes OSPF computed, with their cost in brackets and the next hop,
or `directly attached to <interface>` for a network on this router.
Intra-area, inter-area and external routes are listed together:

```
r1> show ospf route
10.0.0.1/32          [0] directly attached to lo
10.0.0.2/32          [10] via 192.168.12.2, r1-r2
10.0.0.3/32          [15] via 192.168.13.3, r1-r3
10.0.0.4/32          [20] via 192.168.12.2, r1-r2
172.16.4.0/24        [30] via 192.168.12.2, r1-r2
192.168.12.0/24      [10] directly attached to r1-r2
192.168.13.0/24      [15] directly attached to r1-r3
192.168.23.0/24      [20] via 192.168.12.2, r1-r2
192.168.24.0/24      [20] via 192.168.12.2, r1-r2
192.168.34.0/24      [45] via 192.168.13.3, r1-r3
```

172.16.4.0/24 is r4's area-0.0.0.1 network, learned from r4's Summary
LSA.

JSON: an array of `{ prefix, metric, path_type, nexthops: [ { via,
directly_attached, interface, ifindex } ] }`. `path_type` is
`IntraArea`, `InterArea` or `External`; `via` is `null` when
`directly_attached` is true.

### `show ospf graph`

The backbone area's topology as the SPF sees it: each router with its
vertex ID and its links with their costs. A broadcast network is drawn
as direct links between the routers on it.

```
r3> show ospf graph
OSPF Graph (Area 0.0.0.0):

Nodes:
  10.0.0.3 (id: 0)
    Links:
      -> 10.0.0.1 (cost: 15)
      -> 10.0.0.2 (cost: 10)
      -> 10.0.0.4 (cost: 30)
  10.0.0.1 (id: 1)
    Links:
      -> 10.0.0.2 (cost: 10)
      -> 10.0.0.3 (cost: 15)
  10.0.0.2 (id: 2)
    Links:
      -> 10.0.0.1 (cost: 10)
      -> 10.0.0.3 (cost: 10)
      -> 10.0.0.4 (cost: 10)
  10.0.0.4 (id: 3)
    Links:
      -> 10.0.0.2 (cost: 10)
      -> 10.0.0.3 (cost: 30)
```

JSON: `{ area, nodes: [ { id, name, links: [ { to_id, to_name, cost }
] } ] }`.

### `show ospf spf`

The SPF result, one entry per vertex ID of `show ospf graph`: the number
of next hops, the cost, the first-hop vertices in `path`, and
`first_hop_links` as (first-hop vertex, ifindex) pairs.

```
r3> show ospf spf
vertex: 0 nexthops: 1
  metric 0 path []
vertex: 1 nexthops: 1
  metric 15 path [1]
  first_hop_links: [(1, 2)]
vertex: 2 nexthops: 1
  metric 10 path [2]
  first_hop_links: [(2, 3)]
vertex: 3 nexthops: 1
  metric 20 path [2]
  first_hop_links: [(2, 3)]
```

JSON: an array of `{ vertex_id, cost, nexthops, first_hop_links: [ {
vertex_id, link_id } ] }`, with `nexthops` a list of vertex-ID paths.

## Segment Routing and Flexible Algorithm

### `show ospf segment-routing`

The SR-MPLS database of the other SR-capable routers, one section per
router: its SRGB, SRLB and algorithms, then each of its Prefix-SIDs with
the label this router pushes toward it and the outgoing interface and
next hop. See [Segment Routing](ch-08-09-ospf-segment-routing.md).

```
r1> show ospf segment-routing
        OSPF Segment Routing database for ID 10.0.0.1


SR-Node: 10.0.0.2    SRGB: [16000/23999]    SRLB: [15000/15999]    Algo.(s): SPF, FlexAlgo(128)

        Prefix or Link       Node or Adj. SID       Label Operation  Interface          Nexthop
------------------  ---------------------  --------------------  ---------  ---------------
       10.0.0.2/32         SR Pfx (idx 2)            Push 16002      r1-r2     192.168.12.2
       10.0.0.2/32       SR Pfx (idx 102)            Push 16102      r1-r2     192.168.12.2
...
```

JSON: `{ router_id, nodes: [ { router_id, srgb_start, srgb_end,
srlb_start, srlb_end, algorithms, prefix_sids: [ { prefix, sid_type,
sid_value, label_operation, interface, nexthop } ] } ] }`, with
`label_operation` the pushed label.

### `show ospf flex-algo`

The Flexible Algorithm state (RFC 9350), one block per configured
algorithm: its metric type, priority and whether this router advertises
its definition; per area, the definition the algorithm is computed with
— its originator and priority — and whether this router participates;
the per-algorithm SPF, in the `show ospf spf` format; and the
per-algorithm routes with their Flex-Algo Prefix-SID label. See
[Segment Routing](ch-08-09-ospf-segment-routing.md#flexible-algorithm)
for the configuration.

```
r1> show ospf flex-algo
Flex-Algorithm 128
  Metric-Type: igp
  Priority: 128
  Advertise-Definition: true
  Area 0.0.0.0: definition from 10.0.0.4, priority 128; participating
  SPF: 4 reachable node(s)
vertex: 0 nexthops: 1
  metric 0 path []
vertex: 1 nexthops: 1
  metric 10 path [1]
  first_hop_links: [(1, 0)]
vertex: 2 nexthops: 1
  metric 15 path [2]
  first_hop_links: [(2, 0)]
vertex: 3 nexthops: 1
  metric 20 path [1]
  first_hop_links: [(1, 0)]
  Routes:
    10.0.0.2/32  metric 10  label 16102  via 192.168.12.2
    10.0.0.3/32  metric 15  label 16103  via 192.168.13.3
    10.0.0.4/32  metric 20  label 16104  via 192.168.12.2
```

All four routers advertise a definition at the default priority 128, so
the highest Router ID, r4, wins.

JSON: an array of `{ algorithm, metric_type, priority,
advertise_definition, include_any, include_all, exclude_any,
srlg_exclude, spf_reachable_nodes, spf_status, routes: [ { prefix,
metric, label, nexthops } ], selection: [ { area, winner: { router_id,
local, priority, metric_type, calc_type }, participating, reason } ] }`.

## Fast ReRoute (TI-LFA)

TI-LFA (`fast-reroute ti-lfa`) protects each route against the failure
of its primary next-hop router. See
[Fast Failover: TI-LFA + BFD](ch-12-00-nexthop-protect.md).

### `show ospf ti-lfa`

The repair paths of the last SPF, per protected destination router: the
first hop of the post-convergence path and its segment list, as
`Node-SID <router>` and `Adj-SID <from> -> <to>` segments with their
vertex IDs.

```
r1> show ospf ti-lfa
OSPF TI-LFA repair paths:
  Destination 10.0.0.4 (vertex 3)
    [0] first-hop 10.0.0.3 (vertex 2, link_id 3)
        segments:
          Node-SID 10.0.0.3 (vertex 2)
          Adj-SID 10.0.0.3 -> 10.0.0.4 (vertex 2 -> 3)
```

A destination router that is itself the primary next hop gets no
repair, since node protection cannot route around the destination; r2,
adjacent to every other router, prints `(no TI-LFA repair paths computed)`.

JSON: `{ destinations: [ { destination, destination_vertex, repairs: [
{ first_hop, first_hop_vertex, first_hop_link_id, segments: [ { kind,
description } ] } ] } ] }`.

### `show ospf repair-list [detail]`

The TI-LFA backups installed in the RIB, one row per protected route,
with the primary and repair next hops and the label stack the repair
pushes. A destination with a Prefix-SID gets that Prefix-SID last, to
close the stack; `[]` is a repair that needs no segments.

```
r1> show ospf repair-list
Prefix                 Primary via        Repair via         Segments
10.0.0.4/32            192.168.12.2       192.168.13.3       [16003, 15003, 16004]
172.16.4.0/24          192.168.12.2       192.168.13.3       [16003, 15003]
```

r1's repair for r4 goes to r3 (`16003`), takes r3's adjacency to r4
(`15003`) and ends with r4's Prefix-SID (`16004`). A repair that starts
on one of this router's own adjacencies pushes no label for it: the
packet is sent over that adjacency.

`detail` gives the primary and repair next hops with their ifindex and
metric, and one line per label:

```
r1> show ospf repair-list detail
10.0.0.4/32
  Primary: via 192.168.12.2 (ifindex 2), metric 20
  Repair:  via 192.168.13.3 (ifindex 3), metric 21
    sr-mpls 16003
    sr-mpls 15003
    sr-mpls 16004
172.16.4.0/24
  Primary: via 192.168.12.2 (ifindex 2), metric 30
  Repair:  via 192.168.13.3 (ifindex 3), metric 31
    sr-mpls 16003
    sr-mpls 15003
```

The repair metric is the primary's plus one, the metric the backup is
installed with.

JSON: `{ routes: [ { prefix, primary_nexthop, primary_ifindex,
primary_metric, repair_nexthop, repair_ifindex, repair_metric, segments:
[ { kind, value } ] } ] }`.

## Graceful Restart

See [Graceful Restart](ch-08-17-ospf-graceful-restart.md).

### `show ospf graceful-restart`

The helper configuration and drain time, the restart this router has
staged (`clear ospf graceful-restart begin`) or is going through, and
the neighbors this router is currently helping through a restart. On
r1, after `clear ospf graceful-restart begin`:

```
r1> show ospf graceful-restart
Graceful-restart configuration:
  Helper enabled: true
  Max grace period: 1800s
  Strict LSA checking: true
  Drain time: 200ms
  Restart staged: grace=120s, reason=SoftwareRestart, age=3.023385223s

Neighbor ID     Interface  Restart Reason         Grace Period   Remaining
  (no active helpers)
```

and on its neighbor r2, helping it:

```
r2> show ospf graceful-restart
Graceful-restart configuration:
  Helper enabled: true
  Max grace period: 1800s
  Strict LSA checking: true
  Drain time: 200ms

Neighbor ID     Interface  Restart Reason         Grace Period   Remaining
10.0.0.1        if2        SoftwareRestart        120s           116s
```

The `Interface` column shows the interface by its ifindex.

JSON: `{ helper_enabled, max_grace_period_secs, strict_lsa_checking,
drain_time_ms, restarting, helpers: [ { neighbor_id, ifindex,
restart_reason, grace_period_secs, remaining_secs } ] }`, with
`restarting` `{ grace_period_secs, reason, age_secs }` or `null`.

### `show ospf checkpoint`

The graceful-restart checkpoint on disk, which
`clear ospf graceful-restart commit` writes before the daemon exits and
the restarted daemon replays: its format version, write time, grace
period and restart reason, the Router ID, the areas with their LSA
counts, each interface with the neighbors it had (and whether they were
Full), and the Adj-SID labels to keep. The file is
`/var/lib/zebra-rs/checkpoint/ospf.cbor`, or `ospf.cbor` under
`$ZEBRA_OSPF_CHECKPOINT_DIR` when that is set. It exists from the commit
until the restarted daemon loads it, which deletes it, so a running
daemon normally prints the path and `(no checkpoint on disk)`. r1's
checkpoint, as its commit wrote it:

```
r1> show ospf checkpoint
Checkpoint path: /var/lib/zebra-rs/checkpoint/ospf.cbor
  Format version: 1
  Written at: SystemTime { tv_sec: 1792273598, tv_nsec: 408972720 } (grace period 120s, reason 1)
  Router-ID: 10.0.0.1
  Areas: 1
    0.0.0.0 (type: Normal, 27 LSAs)
  Links: 3
    ifindex 1 (lo) area 0.0.0.0 — 0 neighbor(s)
    ifindex 2 (r1-r2) area 0.0.0.0 — 1 neighbor(s)
      10.0.0.2 via 192.168.12.2 (was_full: true)
    ifindex 3 (r1-r3) area 0.0.0.0 — 1 neighbor(s)
      10.0.0.3 via 192.168.13.3 (was_full: true)
  Adj-SID labels: 2
    if2 192.168.12.2 -> label 15000
    if3 192.168.13.3 -> label 15001
```

JSON: `{ path, present, error, format_version, written_at,
grace_period_secs, restart_reason, router_id, areas: [ { area_id,
area_type, lsa_count } ], links: [ { ifindex, ifname, area_id,
neighbors: [ { router_id, interface_addr, was_full } ] } ],
adj_sid_labels: [ { ifindex, address, label } ] }`.
