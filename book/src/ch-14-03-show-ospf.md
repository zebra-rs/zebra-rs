# OSPFv2 and OSPFv3

OSPFv2 (`show ospf …`) and OSPFv3 (`show ospfv3 …`) expose the same set
of operational views: the instance summary, interfaces, neighbors, the
link-state database, the routing table, the SPF tree, and the Segment
Routing / TI-LFA state. The two command trees are near-identical; the
differences are called out below. Every command honors `-j` / `--json`,
and each accepts a `vrf <name>` selector that mirrors the non-VRF
sibling (see the [overview](ch-14-00-show-overview.md)).

See the protocol chapters for configuration:
[OSPF](ch-08-00-ospf.md).

## Instance and adjacencies

### `show ospf` / `show ospfv3`

The instance summary: Router ID, area and interface counts, the time of
and duration of the last SPF run, the TI-LFA compute statistics, and the
per-area SPF-offload gate state.

```
r1> show ospf
 OSPF Routing Process, Router ID: 10.0.0.1
 SPF algorithm last executed 5m12s ago, took 234 usecs
 SPF offload gates:
   area 0.0.0.0: inflight=false, pending=false
```

JSON: an object with `router_id`, `area_count`, `link_count`,
`spf_last_ms_ago`, `spf_duration_us`, `tilfa_compute`, and
`spf_offload_gates`.

### `show ospf interface` / `show ospfv3 interface`

The OSPF-enabled interfaces: area, network type, cost, state (DR/BDR/…),
priority, the elected DR/BDR, the hello/dead timers, and neighbor
counts.

JSON: an array of interface objects (`name`, `ifindex`, `area`, `state`,
`cost`, `priority`, `dr_*`, `bdr_*`, `hello_interval`, `dead_interval`,
`neighbor_count`, …).

### `show ospf neighbor [detail]` / `show ospfv3 neighbor [detail]`

The neighbor table: Router ID, priority, FSM state (`Full/DR`, …),
uptime, dead-time, address, and interface. `detail` adds per-neighbor
state-change history, options, and the DB-summary / LS-request /
retransmission list sizes.

```
r1> show ospf neighbor
Neighbor ID  Pri State         Up Time  Dead Time  Address      Interface
10.0.0.2       1 Full/DR       10m02s   37.123s    192.168.1.2  eth0
10.0.0.3       1 Full/DROther   8m45s   38.456s    192.168.1.3  eth0
```

JSON: an array of neighbor objects; `detail` returns the richer
per-neighbor object.

## Link-state database

### `show ospf database [detail]` / `show ospfv3 database [detail]`

The LSDB. The summary view lists, per area/scope, each LSA's
Link-State ID, advertising router, age, sequence number, and checksum.
`detail` expands every LSA body (links, metrics, prefixes, options).

```
r1> show ospf database

       OSPF Router with ID (10.0.0.1)

Router Link States (Area 0.0.0.0)
Link ID    ADV Router  Age  Seq#       CkSum   Link count
10.0.0.1   10.0.0.1     42  0x80000001 0x1234           3
10.0.0.2   10.0.0.2     45  0x80000001 0x5678           2
```

JSON: an object keyed by area/scope, each holding arrays of LSA-header
objects (`link_id`, `adv_router`, `age`, `seq_number`, `checksum`, …).

> OSPFv3 organizes the LSDB by scope — Area, AS, and Link — to match the
> v3 LSA flooding scopes, where OSPFv2 organizes strictly by area.

## Routes and SPF

### `show ospf route` / `show ospfv3 route`

The OSPF-computed routes with metric, path type, and nexthops.

```
r1> show ospf route
192.168.1.0/24  [10] via 192.168.1.2, eth0
10.0.0.0/24     [20] directly attached to eth1
```

JSON: an array of `{ prefix, metric, path_type, nexthops }`.

### `show ospf spf` / `show ospfv3 spf`

The SPF tree: each vertex with its cost from the root and the nexthop
chain used to reach it.

JSON: an array of SPF-path objects (`vertex_id`, `cost`, `nexthops`).

### `show ospf graph` / `show ospfv3 graph`

The topology graph the SPF runs over — nodes and their costed links.
Useful for visualizing the area before SPF resolves nexthops.

JSON: a graph object with `nodes`, each carrying its `links` (`to_id`,
`cost`).

## Segment Routing and TI-LFA

### `show ospf segment-routing` / `show ospfv3 segment-routing`

The SR-MPLS database: per-router SRGB/SRLB, advertised algorithms, and
Prefix-SID → label-operation mappings. The OSPFv3 form additionally
lists local Adj-SIDs and the installed ILM. See
[Fast Failover: TI-LFA + BFD](ch-12-00-nexthop-protect.md).

JSON: an SR-database object (`router_id`, `nodes`/`interfaces`,
`prefix_sids`, and — v3 — `ilm`, `remote_routers`).

### `show ospfv3 srv6`

OSPFv3 only: the SRv6 operational view — the configured/resolved
locator, the node `End` SID, and the per-adjacency `End.X` SIDs with
their nexthop and LIB twin. See [SRv6](ch-04-00-srv6.md).

JSON: `{ locator, end_sid, end_x_sids: [ … ] }`.

### `show ospf ti-lfa` / `show ospfv3 ti-lfa`

The graph-level TI-LFA repair paths from the last SPF — per destination,
the repair first-hop and the segment list (Node-SID / Adj-SID, or SRv6
segments for v3).

### `show ospf repair-list [detail]` / `show ospfv3 repair-list [detail]`

The TI-LFA backups actually installed in the RIB: one row per protected
prefix with its primary and repair nexthops and the segment stack.
`detail` breaks out each segment with its ifindex and metric.

```
r1> show ospf repair-list
Prefix          Primary via   Repair via    Segments
192.168.1.0/24  192.168.1.2   192.168.1.3   [16000, 16001]
```

JSON: `{ routes: [ { prefix, primary_nexthop, repair_nexthop,
segments, … } ] }`.

### `show ospf flex-algo` / `show ospfv3 flex-algo`

The Flexible Algorithm state (RFC 9350): each configured algorithm's
metric type, priority, affinity constraints, SPF reachability, and the
per-algorithm routes. See the OSPF chapter for configuration.

JSON: an array of flex-algo objects (`algorithm`, `metric_type`,
`priority`, `include_any`/`exclude_any`/…, `spf_status`, `routes`).

## Graceful Restart (OSPFv2)

### `show ospf graceful-restart`

The GR helper configuration (helper enabled, max grace period, strict
LSA checking) and any active helper sessions with their neighbor,
restart reason, and remaining grace time.

JSON: `{ helper_enabled, max_grace_period_secs, strict_lsa_checking,
restarting, helpers: [ … ] }`.

### `show ospf checkpoint`

A diagnostic dump of the on-disk graceful-restart checkpoint: format
version, write time, the captured Router ID / areas / links / neighbors,
and the saved Adj-SID labels. Used to inspect what a restart would
replay.

JSON: a checkpoint object (`path`, `present`, `format_version`,
`router_id`, `areas`, `links`, `adj_sid_labels`, …).
