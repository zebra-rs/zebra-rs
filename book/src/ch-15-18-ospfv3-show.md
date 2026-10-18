# OSPFv3 Show Commands

The `show ospfv3` family reports the instance summary, interfaces and
neighbors, the link-state database, the computed routes, SPF tree and
graph, Segment Routing (SR-MPLS and SRv6), Flexible Algorithm, TI-LFA
and Graceful Restart state. Every command honors `-j` / `--json`; see
[Operational Show Commands](ch-06-03-show-commands.md) for how to run a
show command and request JSON. See [OSPFv3](ch-15-00-ospfv3.md) for the
configuration, and [OSPFv2 Show Commands](ch-08-18-ospf-show.md) for the
`show ospf` family.

`show ospfv3 vrf <name>` runs the summary, `interface`,
`neighbor [detail]`, `database [detail]` or `route` against that VRF's
OSPFv3 instance, with the same output as the default-VRF command. The
other commands have no per-VRF spelling.

The examples come from the four-router network of the OSPFv2 page,
running OSPFv3 alongside OSPFv2 with SR-MPLS (Prefix-SID index 20+*n*
and Flexible Algorithm 128 index 120+*n* on r*n*'s loopback
2001:db8::*n*), TI-LFA and Flexible Algorithm 128:

```
        10          10 (LAN)
   r1 ------- r2 ------------ r4 --- area 0.0.0.1
    \         |              /       (2001:db8:f4::/64)
  15 \     10 |             / 30
      \       |            /
       ------ r3 ----------
```

Everything except 2001:db8:f4::/64 is in area 0.0.0.0, and the link
between r*a* and r*b* is 2001:db8:*ab*::/64. r1–r2, r1–r3, r2–r3 and
r3–r4 are point-to-point links; r2–r4 is a broadcast network with r4 as
its DR and r2 as its BDR. r4 is an ABR: 2001:db8:f4::/64 is a passive
interface in area 0.0.0.1. r1 redistributes the connected network
2001:db8:f1::/64. The SRv6 examples come from the same network with the
SR dataplane switched to SRv6, using uSID locator fcbb:bbbb:*n*::/48 on
r*n*.

## Overview

### `show ospfv3`

The instance summary: Router ID, area and interface counts, when the
last SPF ran and how long it took, the SPF throttle timers, the LSA rate
limits, the TI-LFA computation of the last SPF (only when TI-LFA is
configured), and for each area whether an SPF is running or queued.

```
r1> show ospfv3
OSPFv3 Routing Process
  Router ID:    10.0.0.1
  Areas:        1
  Interfaces:   6
  Last SPF run: 25062 ms ago
  SPF duration: 28 us
  SPF timers:   initial 50 ms, secondary 200 ms, maximum 5000 ms
  MinLSInterval: 5000 ms
  MinLSArrival: 1000 ms
  TI-LFA compute: targets=3 mode=serial workers=1 spf{q=3 pc=3 dedup-saved=0} took 15 us
  SPF offload gates:
    area 0.0.0.0: inflight=false, pending=false
```

`Interfaces` counts every interface the instance tracks, OSPF-enabled
or not.

JSON: `{ router_id, area_count, link_count, spf_last_ms_ago,
spf_duration_us, spf_initial_wait_ms, spf_secondary_wait_ms,
spf_maximum_wait_ms, min_ls_interval_ms, min_ls_arrival_ms,
tilfa_compute, spf_offload_gates: [ { area_id, spf_inflight,
spf_pending } ] }`.

## Interfaces and neighbors

### `show ospfv3 interface`

One block per OSPF-enabled interface: its ifindex, area, interface state
(`DR`, `Backup`, `DROther`, `Point-To-Point`, `Waiting`, …) and neighbor
count; the Interface ID it advertises in its Router-LSA links, the
Instance ID, priority, cost and Hello and Dead intervals; and the DR and
BDR Router IDs of the link.

```
r4> show ospfv3 interface
...
r4-r2 (ifindex 2, area 0.0.0.0, state DR, neighbors 1)
  Interface ID: 2  Instance ID: 0  Priority: 64  Cost: 10  Hello 10s  Dead 40s
  DR: 10.0.0.4  BDR: 10.0.0.2
r4-r3 (ifindex 3, area 0.0.0.0, state Point-To-Point, neighbors 1)
  Interface ID: 3  Instance ID: 0  Priority: 64  Cost: 30  Hello 10s  Dead 40s
  DR: 0.0.0.0  BDR: 0.0.0.0
d4 (ifindex 4, area 0.0.0.1, state DROther, neighbors 0)
  Interface ID: 4  Instance ID: 0  Priority: 64  Cost: 10  Hello 10s  Dead 40s
  DR: 0.0.0.0  BDR: 0.0.0.0
```

JSON: an array of `{ name, ifindex, interface_id, enabled, area_id,
state, d_router, bd_router, priority, cost, hello_interval,
dead_interval, instance_id, neighbor_count }`.

### `show ospfv3 neighbor [detail]`

The neighbor table: the neighbor's Router ID, the local interface, the
neighbor state and the DR the neighbor declares.

```
r2> show ospfv3 neighbor
Router-ID        Iface      State      DR
10.0.0.1         r2-r1      Full       0.0.0.0
10.0.0.3         r2-r3      Full       0.0.0.0
10.0.0.4         r2-r4      Full       10.0.0.4
```

`detail` gives one block per neighbor, adding the neighbor's Interface
ID (in parentheses), its priority and the DR and BDR it declares:

```
r2> show ospfv3 neighbor detail
...
Neighbor 10.0.0.4
  Interface:    r2-r4 (id 2)
  State:        Full
  Priority:     64
  DR / BDR:     10.0.0.4 / 10.0.0.2
```

JSON: an array of `{ router_id, interface, interface_id, state,
priority, d_router, bd_router }`, the same for `detail`.

## Link-state database

### `show ospfv3 database [detail]`

The LSDB by flooding scope: `Area-scope` (the LSAs of every area the
router is in, listed together), `AS-scope` and `Link-scope`. Each row
gives the LSA type, Link State ID (in decimal), advertising router,
sequence number and age. The SR-MPLS and Flexible Algorithm state is
carried in the Router-Info and extended (`E-`) LSAs of RFC 8362.

```
r1> show ospfv3 database
Area-scope:
  Type                     LS-ID            Adv-Router       Seq#       Age
  Router-LSA               0                10.0.0.1         0x80000004 0
  Router-LSA               0                10.0.0.2         0x80000005 1
  Router-LSA               0                10.0.0.3         0x80000004 5
  Router-LSA               0                10.0.0.4         0x80000004 2
  Network-LSA              2                10.0.0.4         0x80000001 2
  Inter-Area-Prefix-LSA    2596542417       10.0.0.4         0x80000001 6
  Intra-Area-Prefix-LSA    0                10.0.0.1         0x8000000b 0
  Intra-Area-Prefix-LSA    0                10.0.0.2         0x80000010 1
  Intra-Area-Prefix-LSA    0                10.0.0.3         0x80000010 6
  Intra-Area-Prefix-LSA    0                10.0.0.4         0x8000000b 2
  Intra-Area-Prefix-LSA    2                10.0.0.4         0x80000002 2
...
AS-scope:
  Type                     LS-ID            Adv-Router       Seq#       Age
  AS-External-LSA          359229540        10.0.0.1         0x80000001 0
  AS-External-LSA          759693980        10.0.0.1         0x80000001 0
  AS-External-LSA          2174584983       10.0.0.1         0x80000001 0
  AS-External-LSA          2920355942       10.0.0.1         0x80000001 0
Link-scope:
  Type                     LS-ID            Adv-Router       Seq#       Age
  Link-LSA                 1                10.0.0.1         0x80000001 0
  Link-LSA                 2                10.0.0.1         0x80000003 0
  Link-LSA                 2                10.0.0.2         0x80000003 6
  Link-LSA                 2                10.0.0.3         0x80000003 6
  Link-LSA                 3                10.0.0.1         0x80000002 0
```

`detail` decodes every LSA, grouped by type and area (or scope): the
header fields, the time left before MaxAge (`Hold remaining`) and, for
this router's own LSAs, before the next refresh, then the body — for
example each Router-LSA link, or each E-Router-LSA link with its
Adj-SID:

```
r1> show ospfv3 database detail
       OSPFv3 Router with ID (10.0.0.1)

                Router-LSA (Area 0.0.0.0)

  Age: 55
  Type: 0x2001 (Router-LSA)
  Link State ID: 0
  Advertising Router: 10.0.0.1
  LS Sequence Number: 0x80000004
  Checksum: 0xb311
  Length: 56
  Hold remaining: 3544s
  Refresh remaining: 1744s
  Flags: 0x02 : E
  Options: V6|E|R

    Type: Point-to-Point
    Metric: 10
    Interface ID: 2
    Neighbor Interface ID: 2
    Neighbor Router ID: 10.0.0.2

    Type: Point-to-Point
    Metric: 15
    Interface ID: 3
    Neighbor Interface ID: 2
    Neighbor Router ID: 10.0.0.3
...
                E-Router-LSA (Area 0.0.0.0)

  Age: 60
  Type: 0xa021 (E-Router-LSA)
  Link State ID: 2
  Advertising Router: 10.0.0.1
  LS Sequence Number: 0x80000001
  Checksum: 0x29d7
  Length: 52
  Hold remaining: 3539s
  Refresh remaining: 1739s
  Router-Link TLV: Type: Point-to-Point
    Metric: 10
    Interface ID: 2
    Neighbor Interface ID: 2
    Neighbor Router ID: 10.0.0.2
    Adj-SID Sub-TLV:
      Flags: 0x60 : V|L
      Weight: 0
      SID/Label: Label: 15003
...
```

JSON: `{ area, as_scope, link }`, each an array of `{ ls_type,
ls_type_raw, link_state_id, advertising_router, ls_seq_number, ls_age,
length, scope }`. `detail` returns the same; the decoded bodies are in
the text form only.

## Routes, SPF and graph

### `show ospfv3 route`

The routes OSPFv3 computed, with their metric and next hop:
`via <link-local>%<ifindex>` for a neighbor, or
`directly attached to <interface>` for a network on this router.
Intra-area, inter-area and external routes are listed together.

```
r1> show ospfv3 route
OSPFv3 routes (10)
  2001:db8::1/128 metric 0 directly attached to lo
  2001:db8::2/128 metric 10 via fe80::c46e:7fff:fe57:98fb%2
  2001:db8::3/128 metric 15 via fe80::5ceb:83ff:fe2f:1ba0%3
  2001:db8::4/128 metric 20 via fe80::c46e:7fff:fe57:98fb%2
  2001:db8:12::/64 metric 10 directly attached to r1-r2
  2001:db8:13::/64 metric 15 directly attached to r1-r3
  2001:db8:23::/64 metric 20 via fe80::c46e:7fff:fe57:98fb%2
  2001:db8:24::/64 metric 20 via fe80::c46e:7fff:fe57:98fb%2
  2001:db8:34::/64 metric 45 via fe80::5ceb:83ff:fe2f:1ba0%3
  2001:db8:f4::/64 metric 30 via fe80::c46e:7fff:fe57:98fb%2
```

JSON: an array of `{ prefix, metric, nexthops: [ { nexthop, ifindex }
] }`.

### `show ospfv3 graph`

The area's topology as the SPF sees it: each router with its vertex ID
and its links with their costs. A broadcast network is drawn as direct
links between the routers on it.

```
r3> show ospfv3 graph
OSPFv3 area graph (4 vertices)
  10.0.0.3 (id 0)
    -> 10.0.0.1 cost 15
    -> 10.0.0.2 cost 10
    -> 10.0.0.4 cost 30
  10.0.0.1 (id 1)
    -> 10.0.0.2 cost 10
    -> 10.0.0.3 cost 15
  10.0.0.2 (id 2)
    -> 10.0.0.1 cost 10
    -> 10.0.0.3 cost 10
    -> 10.0.0.4 cost 10
  10.0.0.4 (id 3)
    -> 10.0.0.2 cost 10
    -> 10.0.0.3 cost 30
```

JSON: an array of `{ id, name, links: [ { from, to, cost } ] }`.

### `show ospfv3 spf`

The SPF tree: each router with its cost and the first-hop router (or
`(self)`) that reaches it.

```
r3> show ospfv3 spf
OSPFv3 SPF tree (4 vertices)
  10.0.0.3 cost 0 via (self)
  10.0.0.1 cost 15 via 10.0.0.1
  10.0.0.2 cost 10 via 10.0.0.2
  10.0.0.4 cost 20 via 10.0.0.2
```

JSON: an array of `{ vertex_id, router_id, cost, first_hop_routers }`.

## Segment Routing and Flexible Algorithm

### `show ospfv3 segment-routing`

The SR-MPLS state (RFC 8666). The header gives whether SR-MPLS is
enabled and the local SRGB and SRLB. The interface table lists each
OSPF interface with its network type and Prefix-SID index, and each
adjacency's Adj-SID on the line below as `nbr=<router> lbl=<label>`.
`Local ILM` lists the labels this router installed — its Adj-SIDs and
the Prefix-SIDs it forwards — with their operation (`Swap` to keep the
label, `Pop` to remove it), next hop and interface.
`Remote Prefix-SIDs` gives each other SR router's SRGB and SRLB and its
Prefix-SIDs with the label this router pushes toward them. See
[Segment Routing (SR-MPLS)](ch-15-10-ospfv3-segment-routing.md).

```
r1> show ospfv3 segment-routing
  OSPFv3 Segment Routing database for ID 10.0.0.1
  State: enabled
  Local SRGB: [16000/23999]   SRLB: [15000/15999]

  Interface     Network         Prefix-SID      Adj-SID
  --------------------------------------------------------------------------
  lo            BROADCAST       idx 21          -
  r1-r2         POINT-TO-POINT  -               -
                                                nbr=10.0.0.2 lbl=15003
  r1-r3         POINT-TO-POINT  -               -
                                                nbr=10.0.0.3 lbl=15002

  Local ILM (v3): 9 entries
  Label     Type                    Via                               Iface
  ------------------------------------------------------------------------
  15002     Pop SR Adj              fe80::5ceb:83ff:fe2f:1ba0         r1-r3
  15003     Pop SR Adj              fe80::c46e:7fff:fe57:98fb         r1-r2
  16021     Pop SR Pfx (idx 21)     ::1                               lo
  16022     Swap SR Pfx (idx 22)    fe80::c46e:7fff:fe57:98fb         r1-r2
  16023     Swap SR Pfx (idx 23)    fe80::5ceb:83ff:fe2f:1ba0         r1-r3
  16024     Swap SR Pfx (idx 24)    fe80::c46e:7fff:fe57:98fb         r1-r2
  16122     Swap SR Pfx (idx 122)   fe80::c46e:7fff:fe57:98fb         r1-r2
  16123     Swap SR Pfx (idx 123)   fe80::5ceb:83ff:fe2f:1ba0         r1-r3
  16124     Swap SR Pfx (idx 124)   fe80::c46e:7fff:fe57:98fb         r1-r2

  Remote Prefix-SIDs:

  SR-Node: 10.0.0.2    Area: 0.0.0.0    SRGB: [16000/23999]    SRLB: [15000/15999]
    Prefix                            Prefix-SID          Label Op        Iface      Nexthop
    ----------------------------------------------------------------------------------
    2001:db8::2/128                   SR Pfx (idx 22)     Push 16022      r1-r2      fe80::c46e:7fff:fe57:98fb
    2001:db8::2/128                   SR Pfx (idx 122)    Push 16122      r1-r2      fe80::c46e:7fff:fe57:98fb
...
```

With SRv6 as the dataplane, it reads `State: disabled` and the ILM is
empty.

JSON: `{ enabled, router_id, srgb_start, srgb_end, srlb_start,
srlb_end, interfaces: [ { name, network_type, prefix_sid,
adjacency_sid, lan_adj_sids: [ { neighbor_router_id, label } ] } ], ilm:
[ { label, ilm_type, via, interface } ], remote_routers: [ {
advertising_router, area, srgb, srlb, prefixes: [ { prefix, sid_form,
label_op, interface, nexthop } ] } ] }`.

### `show ospfv3 srv6`

The SRv6 state (RFC 9513): the locator, its node (`End`) SID, and one
End.X SID per adjacency with its behavior, the neighbor's global address
it forwards to, and its LIB twin — the `fcbb:bbbb:e0xx::` form used
when the SID follows another uSID in a packed container. See
[SRv6](ch-15-11-ospfv3-srv6.md).

```
r1> show ospfv3 srv6
OSPFv3 SRv6:
  Locator: LOC1 (fcbb:bbbb:1::/48, usid)
  End SID: fcbb:bbbb:1:: (uN)

Local SRv6 End.X SIDs:
 Interface  Neighbor        SID                      Behavior Nexthop                  LIB
 r1-r2      10.0.0.2        fcbb:bbbb:1:e000::       uA       2001:db8:12::2           fcbb:bbbb:e000::
 r1-r3      10.0.0.3        fcbb:bbbb:1:e001::       uA       2001:db8:13::3           fcbb:bbbb:e001::
```

Without a locator it prints `Locator: (not configured)`.

JSON: `{ locator: { name, prefix, behavior }, end_sid: { sid, behavior
}, end_x_sids: [ { interface, neighbor_router_id, sid, behavior,
nexthop, lib_sid } ] }`, with `locator` and `end_sid` `null` when no
locator is configured.

### `show ospfv3 flex-algo`

The Flexible Algorithm state (RFC 9350), one block per configured
algorithm: its metric type, priority and whether this router advertises
its definition; per area, the definition the algorithm is computed with
— its originator and priority — and whether this router participates;
the per-algorithm SPF tree; and the per-algorithm routes with their
Flex-Algo Prefix-SID label.

```
r1> show ospfv3 flex-algo
Flex-Algorithm 128
  Metric-Type: igp
  Priority: 128
  Advertise-Definition: true
  Area 0.0.0.0: definition from 10.0.0.4, priority 128; participating
  SPF: 4 reachable node(s)
    10.0.0.1 cost 0 via (self)
    10.0.0.2 cost 10 via 10.0.0.2
    10.0.0.3 cost 15 via 10.0.0.3
    10.0.0.4 cost 20 via 10.0.0.2
  Routes:
    2001:db8::2/128  metric 10  label 16122  via fe80::c46e:7fff:fe57:98fb
    2001:db8::3/128  metric 15  label 16123  via fe80::5ceb:83ff:fe2f:1ba0
    2001:db8::4/128  metric 20  label 16124  via fe80::c46e:7fff:fe57:98fb
```

All four routers advertise a definition at the default priority 128, so
the highest Router ID, r4, wins. On r4, an ABR, the block has a line per
area:

```
r4> show ospfv3 flex-algo
...
  Area 0.0.0.0: definition from 10.0.0.4, this router, priority 128; participating
  Area 0.0.0.1: definition from 10.0.0.4, this router, priority 128; participating
...
```

JSON: an array of `{ algorithm, metric_type, priority,
advertise_definition, include_any, include_all, exclude_any,
srlg_exclude, spf_status, spf_nodes: [ { router_id, cost, via } ],
routes: [ { prefix, metric, label, nexthops } ], selection: [ { area,
winner: { router_id, local, priority, metric_type, calc_type },
participating } ] }`.

## Fast ReRoute (TI-LFA)

TI-LFA (`fast-reroute ti-lfa`) protects each route against the failure
of its primary next-hop router, with SR-MPLS labels or SRv6 SIDs. See
[Fast Failover: TI-LFA + BFD](ch-12-00-nexthop-protect.md).

### `show ospfv3 ti-lfa`

The repair paths of the last SPF, per protected destination router: the
first hop of the post-convergence path and its segment list, as
`Node-SID <router>` and `Adj-SID <from> -> <to>` segments with their
vertex IDs. The same list serves both dataplanes.

```
r1> show ospfv3 ti-lfa
OSPFv3 TI-LFA repair paths:
  Destination 10.0.0.4 (vertex 3)
    [0] first-hop 10.0.0.3 (vertex 2, link_id 3)
        segments:
          Node-SID 10.0.0.3 (vertex 2)
          Adj-SID 10.0.0.3 -> 10.0.0.4 (vertex 2 -> 3)
```

A destination router that is itself the primary next hop gets no
repair, since node protection cannot route around the destination.

JSON: `{ destinations: [ { destination, destination_vertex, repairs: [
{ first_hop, first_hop_vertex, first_hop_link_id, segments: [ { kind,
description } ] } ] } ] }`.

### `show ospfv3 repair-list [detail]`

The TI-LFA backups installed in the RIB, one row per protected route,
with the primary and repair next hops and the segments the repair
imposes. With SR-MPLS, a destination with a Prefix-SID gets that
Prefix-SID last, to close the stack:

```
r1> show ospfv3 repair-list
Prefix                         Primary via                Repair via                 Segments
2001:db8::4/128                fe80::c46e:7fff:fe57:98fb  fe80::5ceb:83ff:fe2f:1ba0  [16023, 15002, 16024]
2001:db8:24::/64               fe80::c46e:7fff:fe57:98fb  fe80::5ceb:83ff:fe2f:1ba0  [16023, 15002]
2001:db8:f4::/64               fe80::c46e:7fff:fe57:98fb  fe80::5ceb:83ff:fe2f:1ba0  [16023, 15002]
```

r1's repair for r4 goes to r3 (`16023`), takes r3's adjacency to r4
(the middle label, r3's Adj-SID for it) and ends with r4's Prefix-SID
(`16024`). With SRv6 the same
two segments, r3's End SID and r3's End.X toward r4, pack into one uSID
container, inserted as an SRH ahead of the original destination:

```
r1> show ospfv3 repair-list
Prefix                         Primary via                Repair via                 Segments
2001:db8::4/128                fe80::c46e:7fff:fe57:98fb  fe80::5ceb:83ff:fe2f:1ba0  [fcbb:bbbb:3:e002::]
2001:db8:24::/64               fe80::c46e:7fff:fe57:98fb  fe80::5ceb:83ff:fe2f:1ba0  [fcbb:bbbb:3:e002::]
2001:db8:f4::/64               fe80::c46e:7fff:fe57:98fb  fe80::5ceb:83ff:fe2f:1ba0  [fcbb:bbbb:3:e002::]
fcbb:bbbb:4::/48               fe80::c46e:7fff:fe57:98fb  fe80::5ceb:83ff:fe2f:1ba0  [fcbb:bbbb:3:e002::]
```

`detail` gives the primary and repair next hops with their ifindex and
metric, and one line per label (`sr-mpls`) or SID (`srv6`):

```
r1> show ospfv3 repair-list detail
2001:db8::4/128
  Primary: via fe80::c46e:7fff:fe57:98fb (ifindex 2), metric 20
  Repair:  via fe80::5ceb:83ff:fe2f:1ba0 (ifindex 3), metric 21
    sr-mpls 16023
    sr-mpls 15002
    sr-mpls 16024
...
```

The repair metric is the primary's plus one, the metric the backup is
installed with.

JSON: `{ routes: [ { prefix, primary_nexthop, primary_ifindex,
primary_metric, repair_nexthop, repair_ifindex, repair_metric, segments:
[ { kind, value } ] } ] }`.

## Graceful Restart

See [Graceful Restart](ch-15-12-ospfv3-graceful-restart.md).

### `show ospfv3 graceful-restart`

The helper configuration and drain time, the restart this router has
staged (`clear ospfv3 graceful-restart begin`) or is going through, and
the neighbors this router is currently helping through a restart. On
r1, after `clear ospfv3 graceful-restart begin`:

```
r1> show ospfv3 graceful-restart
Graceful-restart configuration:
  Helper enabled: true
  Max grace period: 1800s
  Strict LSA checking: true
  Drain time: 200ms
  Restart staged: grace=120s, reason=SoftwareRestart, age=3.064471507s

Neighbor ID     Interface        Restart Reason         Grace Period   Remaining
  (no active helpers)
```

and on its neighbor r2, helping it:

```
r2> show ospfv3 graceful-restart
Neighbor ID     Interface        Restart Reason         Grace Period   Remaining
10.0.0.1        r2-r1            SoftwareRestart        120s           116s
```


JSON: `{ helper_enabled, max_grace_period_secs, strict_lsa_checking,
drain_time_ms, restarting, helpers: [ { neighbor_id, interface,
ifindex, restart_reason, grace_period_secs, remaining_secs } ] }`, with
`restarting` `{ grace_period_secs, reason, age_secs }` or `null`.

### `show ospfv3 checkpoint`

The graceful-restart checkpoint on disk, which
`clear ospfv3 graceful-restart commit` writes before the daemon exits
and the restarted daemon replays: the Router ID, grace period, area and
LSA counts, and each interface with the neighbors it had (and whether
they were Full). The file is `/var/lib/zebra-rs/checkpoint/ospfv3.cbor`,
or `ospfv3.cbor` under `$ZEBRA_OSPF_CHECKPOINT_DIR` when that is set. It
exists from the commit until the restarted daemon loads it, which
deletes it, so a running daemon normally prints `No checkpoint at
<path>`. r1's checkpoint, as its commit wrote it:

```
r1> show ospfv3 checkpoint
Checkpoint: /var/lib/zebra-rs/checkpoint/ospfv3.cbor
  Router ID: 10.0.0.1
  Grace period: 120s
  Areas: 1 (32 LSAs), Links: 3
  Link r1-r2 (2): neighbor 10.0.0.2 was_full=true
  Link r1-r3 (3): neighbor 10.0.0.3 was_full=true
```

JSON: `{ path, present, error, router_id, grace_period_secs, areas,
lsas, links }`, with the last three as counts.
