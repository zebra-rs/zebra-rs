# IS-IS Show Commands

The `show isis` family reports adjacencies, the link-state database, the
SPF results and routing table, DIS election, Fast ReRoute (TI-LFA),
Flexible Algorithm, Area Proxy and Graceful Restart state. Every command
honors `-j` / `--json`; see
[Operational Show Commands](ch-06-03-show-commands.md) for how to run a
show command and request JSON.

Most views are organized per **level** (L1 / L2) and, where relevant,
per address family (IPv4 / IPv6). See [IS-IS](ch-07-00-isis.md) for the
configuration.

`show isis vrf <name>` runs `summary`, `neighbor`, `database`, `route`,
`interface` or `topology` against that VRF's IS-IS instance, with the
same output as the default-VRF command. The other commands, and the
`detail` forms, have no per-VRF spelling.

The examples come from a four-router level-2 network running SR-MPLS
(Prefix-SID index *n* on r*n*), TI-LFA and Flexible Algorithm 128:

```
        10          10 (LAN)
   r1 ------- r2 ------------ r4
    \         |              /
  15 \     10 |             / 30
      \       |            /
       ------ r3 ----------
```

r1–r2, r1–r3, r2–r3 and r3–r4 are point-to-point links; r2–r4 is a LAN
with r4 as its DIS.

## Overview

### `show isis`

Prints only the command name today; JSON `{}`. Use `show isis summary`
for the operational digest.

### `show isis summary`

The LSP buffer size this router originates with, the L1 area-password
and L2 domain-password authentication (each only when set, with
`, send-only` when so configured), and the configured SRv6 locator's
status (only when a locator is configured).

```
r1> show isis summary
LSP MTU: 1492 bytes
Domain-password (L2): mode md5, key-id 1
```

With an SRv6 locator, a table follows:

```
SRv6 Locator:
Name                 Prefix                   Behavior Status
-------------------- ------------------------ -------- -------
LOC_N1               2001:db8:a:1::/64        Classic  Up
```

An unresolved locator shows `Down` with an empty prefix and behavior.

JSON: `{ lsp_mtu, area_password, domain_password, srv6_locator }`. The
passwords are `{ mode, key_id, send_only }` and the locator is
`{ name, prefix, behavior, status }`, each `null` when not configured.

### `show isis hostname`

The dynamic-hostname mappings (TLV 137) learned per level. `*` marks this
router's own entry.

```
r1> show isis hostname
Level  System ID      Hostname
L2   * 0000.0000.0001 r1
L2     0000.0000.0002 r2
L2     0000.0000.0003 r3
L2     0000.0000.0004 r4
```

With no entries the command prints `% No hostname was found`.

JSON: `{ l1: { <system-id>: [ hostname, local ] }, l2: { … } }`. Each
value is the hostname and whether this router originated it.

## Adjacencies and interfaces

### `show isis neighbor [detail]`

The adjacencies per interface and level. `System Id` shows the hostname
when one is known, `Holdtime` is the seconds left on the hold timer, and
`State` is `Up`, `Init` or `Down`.

```
r2> show isis neighbor
System Id           Interface   L  State         Holdtime SNPA
r1                  r2-r1       2  Up            29       0608.16c8.30e8
r3                  r2-r3       2  Up            29       aaa6.2f25.9813
r4                  r2-r4       2  Up            29       b636.2c24.bbe6
```

`detail` gives one block per adjacency: interface, level and state;
circuit type and the protocols the neighbor speaks; SNPA and LAN ID; LAN
priority and whether the neighbor is the DIS; then its IPv4 addresses
(each with the Adj-SID label this router allocated for the adjacency),
IPv6 link-local addresses and IPv6 prefixes.

```
r2> show isis neighbor detail
...
 r4
    Interface: r2-r4, Level: L2, State: Up
    Circuit type: L2, Speaks: IPv4
    SNPA: b636.2c24.bbe6, LAN id: 0000.0000.0004.02
    LAN Priority: 64, is DIS
    IP Prefixes
      192.168.24.4 (15002)
```

On a point-to-point circuit the LAN ID and priority read zero.

JSON: an array of `{ system_id, interface, level, state, hold_time,
snpa }`. `detail` adds `circuit_type` (1 = L1, 2 = L2, 3 = L1L2),
`speaks`, `lan_id`, `lan_priority`, `is_dis`, `ip_prefixes`
(`{ address, label }`), `ipv6_link_locals` and `ipv6_prefixes`.

### `show isis interface [detail]`

The IS-IS circuits: circuit ID, network type, level, DIS role and
adjacency. `DIS` is `N/A` on a point-to-point or loopback circuit, and on
a LAN `DIS` (this router), `Other` or `Selecting`. `Adjacency` is `Up`
with the LAN ID (or the neighbor's ID on point-to-point), or `Down`.

```
r2> show isis interface
  Interface   CircId   State    Type     Level DIS       Adjacency
  lo          0x01     Up       lan      L2    N/A       Down
  r2-r1       0x02     Up       p2p      L2    N/A       Up 0000.0000.0001.00
  r2-r3       0x03     Up       p2p      L2    N/A       Up 0000.0000.0003.00
  r2-r4       0x04     Up       lan      L2    Other     Up 0000.0000.0004.02
```

`detail` gives one block per circuit:

```
r2> show isis interface detail
...
Interface: r2-r4, State: Up, Active, Circuit Id: 0x04
  Type: lan, Level: L2, SNPA: 4a:de:77:f8:72:07, MTU: 1500
  LSP MTU: 1497
  Level-2 Information:
    Metric: 10, Active neighbors: 1
    Hello interval: 3, Holddown count: 10, Padding: yes
    CSNP interval: 10, PSNP interval: 2
    LAN priority: 64, DIS status: Other
    Adjacency: Up 0000.0000.0004.02
```

Each level block then dumps the last Hello sent on the circuit. A
`Hello Authentication:` block (mode, key ID, send-only, and the
tx-signed / rx-good / rx-bad / rx-no-auth counters) follows when hello
authentication is configured, then the circuit's IPv4 prefixes (with a
`(secondary)` tag where it applies), IPv6 link-local addresses and IPv6
prefixes. `LSP MTU:` adds `(exceeds interface MTU …)` when it is larger
than the interface MTU.

JSON: an array of `{ name, ifindex, circuit_id, is_up, network_type,
level, dis, adjacency }`. `detail` returns `{ interface, state, active,
circuit_id, type, level, snpa, mtu, lsp_mtu, lsp_mtu_exceeds_interface,
level_1_info, level_2_info, authentication, ip_prefixes,
ipv6_link_locals, ipv6_prefixes }`, leaving out what does not apply.
The level blocks are `{ metric, active_neighbors, hello_interval,
holddown_count, padding, csnp_interval, psnp_interval, lan_priority,
dis, adjacency }`.

### `show isis dis statistics` / `show isis dis history`

DIS (Designated IS) election diagnostics. `statistics` shows, per circuit
and level, this router's DIS status (`Myself`, `Other` or `None`), the
current DIS (`Self`, its LAN ID, or `-`), how many times the DIS changed,
how long this router has been DIS, and when the DIS last changed.

```
r2> show isis dis statistics
DIS Statistics:
Interface        Level  Status      DIS              Flaps  Uptime     Last Change
---------------- ------ ----------- ---------------- ------ ---------- -----------
lo               2      None        -                0      -          -
r2-r1            2      None        -                0      -          -
r2-r3            2      None        -                0      -          -
r2-r4            2      Other       0000.0000.0004.02 1      -          54s ago
```

`history` is the log of DIS changes, up to 50 per circuit and level:

```
r2> show isis dis history
DIS Change History:
Interface        Level  Time                From        To          Reason
---------------- ------ ------------------- ----------- ----------- ------
r2-r4            2      54s ago             None        Other       Neighbor is 0000.0000.0004 elected (priority: 64, mac: b6:36:2c:24:bb:e6)
```

JSON: `statistics` is an array of `{ interface, level, current_status,
current_dis, flap_count, uptime, last_change, history_count }`, where
`current_status` is `NotSelected`, `Myself` or `Other`. `history` is an
array of `{ interface, level, timestamp, from_status, to_status,
from_sys_id, to_sys_id, reason }`; `from_sys_id` is `null` when there
was no DIS before.

## Database

### `show isis database [detail]`

The LSDB: one row per LSP, all level-1 LSPs first, then level-2, with no
header. Each row gives the LSP ID (with the hostname when known), `*` for
this router's own LSPs, the PDU length, sequence number, checksum,
remaining lifetime, and the ATT/P/OL bits. `r4.02-00` is r4's pseudonode
LSP for the LAN.

```
r1> show isis database
r1.00-00                  *      192  0x00000002  0x3738      1152  0/0/0
r2.00-00                         226  0x00000002  0x2062      1150  0/0/0
r3.00-00                         220  0x00000002  0x51e2      1151  0/0/0
r4.00-00                         198  0x00000002  0xda1b      1149  0/0/0
r4.02-00                          70  0x00000001  0x6a95      1145  0/0/0
```

When an originator has more than one fragment, or is missing fragment 0,
a `Fragment Summary` table for its level comes first.

`detail` prints a header per level and each LSP's TLVs under its row:

```
r1> show isis database detail

L2 Link State Database:
LSP ID                        PduLen  SeqNumber   Chksum  Holdtime  ATT/P/OL
r1.00-00                  *      192  0x00000002  0x3738      1152  0/0/0
  Area address: 49.0001
  Protocol Supported: IPv4
  LSP Buffer Size: 1492
  Hostname: r1
  Router Capability: 10.0.0.1, D:0 S:0
   Segment Routing: I:1 V:1, Global Block: Label(16000), Range: 8000
   Segment Routing Algorithm: SPF(0) FlexAlgo(128)
   Segment Routing Local Block: Label(15000), Range: 1000
   Flex-Algorithm Definition: Algo 128, Metric-Type 0, Calc-Type 0, Priority 128
  TE Router ID: 10.0.0.1
...
```

JSON: `{ level_1, level_2 }`, arrays of `{ lsp_id, system_id,
originated, pdu_len, seq_number, checksum, holdtime, att_bit, p_bit,
ol_bit }`. `detail` returns one array of decoded LSPs from both levels,
`{ pdu_len, hold_time, lsp_id, seq_number, checksum, types, tlvs }`,
where `hold_time` is the lifetime carried in the LSP.

## Routes, topology and SPF

### `show isis route [detail]`

Per level, the IPv4 SPF tree and IPv4 routing table, then the IPv6 tree
and table, and a `Local SRv6 SIDs:` table when SRv6 is enabled. The
`Label(s)` column is the route's Prefix-SID label, marked `(impl-null)`
when the next hop is the destination and pops it.

```
r1> show isis route
Area 49.0001:

IS-IS paths to level-2 routers that speak IP
 Vertex                 Type          Metric  Next-Hop  Interface  Parent
 -------------------------------------------------------------------------
 r1
 10.0.0.1/32            IP internal   0                            r1
 192.168.12.0/24        IP internal   0                            r1
 192.168.13.0/24        IP internal   0                            r1
 r2                     TE-IS         10      r2        r1-r2      r1
 r3                     TE-IS         15      r3        r1-r3      r1
 r4                     pseudo_TE-IS  20      r2        r1-r2      r2
 r4                     TE-IS         20      r2        r1-r2      r4
 10.0.0.2/32            IP TE         20      r2        r1-r2      r2
 192.168.12.0/24        IP TE         20      r2        r1-r2      r2
 192.168.23.0/24        IP TE         20      r2        r1-r2      r2
 192.168.24.0/24        IP TE         20      r2        r1-r2      r2
 10.0.0.3/32            IP TE         25      r3        r1-r3      r3
 192.168.23.0/24        IP TE         25      r3        r1-r3      r3
 10.0.0.4/32            IP TE         30      r2        r1-r2      r4
 192.168.13.0/24        IP TE         30      r3        r1-r3      r3
 192.168.24.0/24        IP TE         30      r2        r1-r2      r4
 192.168.34.0/24        IP TE         45      r3        r1-r3      r3
 192.168.34.0/24        IP TE         50      r2        r1-r2      r4

IS-IS L2 IPv4 routing table:

 Prefix             Metric  Interface  Nexthop          Label(s)
 ---------------------------------------------------------------
 10.0.0.2/32        20      r1-r2      192.168.12.2     16002 (impl-null)
 10.0.0.3/32        25      r1-r3      192.168.13.3     16003 (impl-null)
 10.0.0.4/32        30      r1-r2      192.168.12.2     16004
 192.168.12.0/24    20      r1-r2      192.168.12.2     -
 192.168.13.0/24    30      r1-r3      192.168.13.3     -
 192.168.23.0/24    20      r1-r2      192.168.12.2     -
 192.168.24.0/24    20      r1-r2      192.168.12.2     -
 192.168.34.0/24    45      r1-r3      192.168.13.3     -

IS-IS paths to level-2 routers that speak IPv6
 Vertex                 Type          Metric  Next-Hop  Interface  Parent
 -------------------------------------------------------------------------

IS-IS L2 IPv6 routing table:

 Prefix                 Metric  Interface  Nexthop                    Label(s)
 -----------------------------------------------------------------------------
```

`detail` leaves out the SPF trees and lists each route with its next
hops, the neighbor's SRGB base and the Prefix-SID label:

```
r1> show isis route detail
Area 49.0001:

IS-IS L2 IPv4 routing table:

L2 10.0.0.2/32 [metric 20]
  via 192.168.12.2, r1-r2, r2, SRGB Base: 16000
    Prefix-SID: 16002 (impl-null)
L2 10.0.0.3/32 [metric 25]
  via 192.168.13.3, r1-r3, r3, SRGB Base: 16000
    Prefix-SID: 16003 (impl-null)
L2 10.0.0.4/32 [metric 30]
  via 192.168.12.2, r1-r2, r2, SRGB Base: 16000
    Prefix-SID: 16004
    Backup path: TI-LFA, via 192.168.13.3, r1-r3 r3
      Labels imposed { 16003 15002 16004 }
      P node: r3, Label: 16003
...
```

A route protected by TI-LFA, like 10.0.0.4/32 here, adds a
`Backup path: TI-LFA, via <address>, <interface> <neighbor>` line, the
label stack it imposes (`Labels imposed { … }`: the repair segments,
then the destination's own Prefix-SID), and a `P node:` line naming the
router whose Node-SID starts the repair — only the label when the repair
starts with an Adj-SID. A repair with no segments besides the
destination's Prefix-SID prints `(trivial repair, no SR segments)` in
place of the `P node:` line. `show isis repair-list` shows the same
repairs as a table.

JSON: `{ level_1, level_2 }`, arrays of `{ prefix, metric, nexthops }`
with `nexthops` of `{ address, interface, label, implicit_null }`
(`label` and `implicit_null` only when set). It covers IPv4 routes only,
and `detail` returns the same JSON.

### `show isis topology`

The per-level SPF trees for IPv4 and IPv6 — the trees `show isis route`
prints, without the routing tables. Each vertex lists its metric, first
hop, interface and parent, followed by the prefixes it advertises. With
multi-topology IPv6 (MT 2), the IPv6 tree comes from the MT 2 SPF.

JSON: `{ area, levels: [ { level, ipv4, ipv6, ipv6_mt2 } ] }`. Each
vertex is `{ vertex, system_id, is_self, metric, nexthop, interface,
parent, prefixes }` and each prefix `{ prefix, type, metric, nexthop,
interface }`; empty and false fields are left out.

### `show isis spf [detail]`

The SPF state: whether TI-LFA and SR-MPLS / SRv6 are enabled, per-level
SPF statistics (last run, duration, and the TI-LFA computation), then per
topology each destination's cost, next hops and paths. `detail` is
accepted and prints the same view.

```
r1> show isis spf
TI-LFA: enabled (sr-mpls: on, srv6: off)
SPF stats:
  L1: never run, inflight=false, pending=false
  L2: last 47.056s ago, took 564μs, inflight=false, pending=false
      ti-lfa: targets=3 mode=serial workers=1 spf{q=3 pc=3 dedup-saved=0} took 239μs

L2 (single-topology / MT 0) SPF results:
  Destination r1, cost 0
    (no nexthop — self or unreachable)
    paths:
      [0] (empty)
  Destination r2, cost 10
    [0] nexthop r2 (r1-r2)
    paths:
      [0] r2
  Destination r3, cost 15
...
```

JSON: `{ ti_lfa_enabled, sr_mpls_enabled, sr_srv6_enabled, detail,
topologies }`. `topologies` is keyed by topology name
(`"L2 (single-topology / MT 0)"`, `"L2 (MT 2 / IPv6 unicast)"`, …), each
`{ destinations: [ { vertex_id, name, cost, nexthops, paths } ] }`. The
SPF statistics are in the text view only.

### `show isis graph`

The SPF graph per level: each node with its outgoing (`->`) and incoming
(`<-`) links and their costs. It is the single-topology (MT 0) graph.

```
r1> show isis graph

L2 IS-IS Graph:

Nodes:
  r1 [0000.0000.0001] (id: 0)
    Links:
      -> r2 (cost: 10)
      -> r3 (cost: 15)
      <- r2 (cost: 10)
      <- r3 (cost: 15)
...
```

JSON: an array of `{ level, nodes: [ { id, name, sys_id, olinks,
ilinks } ] }`, links being `{ id, name, cost, te }`; `te` carries the
measured delay and loss when the link advertises them.

## Fast ReRoute (TI-LFA)

TI-LFA protects a route against the failure of its primary next-hop
router, so a destination that is that neighbor itself gets no repair. In
the example network only 10.0.0.4/32 (r4) is protected on r1: its primary
path runs through r2, and the repair goes to r3 and then over the r3–r4
link, which r3 would not use on its own. See
[Fast Failover: TI-LFA + BFD](ch-12-00-nexthop-protect.md).

### `show isis fast-reroute [summary]`

Per-level protection tallies for IPv4 and IPv6: total prefixes,
protected and unprotected, and the protected ones by repair size. The
breakdown appears only when something is protected, and an address
family only when it has routes. `show isis fast-reroute` alone is the
same view.

```
r1> show isis fast-reroute summary
Area 49.0001:

  Level-2:
    IPv4:
      Total prefixes:        8
      Protected:             1
        Trivial repair:      0
        1-segment SR:        0
        N-segment SR:        1
      Unprotected:           7
```

The repair size counts the repair's own segments: r4's repair is r3's
Node-SID and the r3→r4 Adj-SID, so it is N-segment. The destination's
Prefix-SID that closes an SR-MPLS label stack is not counted.

JSON: `{ area, levels: [ { level, ipv4, ipv6 } ] }`, with `level`
`"Level-1"` / `"Level-2"` and each family `{ total, protected,
unprotected, trivial, one_segment, multi_segment }`.

### `show isis fast-reroute prefix <A.B.C.D/M> [detail]`

One IPv4 prefix as `show isis route detail` prints it, with
`Protected by TI-LFA` or `Unprotected (no TI-LFA backup stamped)` under
its header line. A prefix that is not in the IS-IS RIB prints
`% No route for <prefix> in IS-IS RIB`. `detail` is optional.

```
r1> show isis fast-reroute prefix 10.0.0.4/32
L2 10.0.0.4/32 [metric 30]
  Protected by TI-LFA
  via 192.168.12.2, r1-r2, r2, SRGB Base: 16000
    Prefix-SID: 16004
    Backup path: TI-LFA, via 192.168.13.3, r1-r3 r3
      Labels imposed { 16003 15002 16004 }
      P node: r3, Label: 16003
```

JSON: `{ prefix, found, entries: [ { level, metric, protected, nexthops:
[ { address, interface, has_backup } ] } ] }`.

### `show isis micro-loop-avoidance`

The micro-loop avoidance state: whether it is operational or why not
(`not configured`, `ti-lfa disabled`, `backup-as-primary enabled`,
`RIB distribution disabled`, `graceful restart active`), the RIB update
delay, and per level the phase (`idle`, `candidate` or `holding`), the
committed and last-SPF self-LSP generations, and lifetime counters.
While a failure is being handled, the level also shows the failure and
its cause, the topology gate, the remaining hold time and the IPv4 / IPv6
prefixes held.

```
r1> show isis micro-loop-avoidance
IS-IS micro-loop avoidance: not configured
  RIB update delay: 5000 ms
  Level-1: idle
    Self-LSP generation: committed 0, last SPF 0
    Counters: events 0, holds 0, deferred 0, releases 0, aborts 0, activation-failures 0, topology-waits 0, topology-timeouts 0, no-eligible 0, suppressed 0, last/max hold N/A/0 ms
  Level-2: idle
    Self-LSP generation: committed 2, last SPF 2
    Counters: events 0, holds 0, deferred 0, releases 0, aborts 0, activation-failures 0, topology-waits 0, topology-timeouts 0, no-eligible 0, suppressed 0, last/max hold N/A/0 ms
```

JSON: `{ enabled, operational, inactive_reason, rib_update_delay_ms,
levels: [ … ] }`, with both levels always present.

### `show isis ti-lfa`

The repair paths the last SPF computed, per level and destination: the
repair's first hop and its segments, `NodeSid(<node>)` and
`AdjSid(<from>, <to>)`. The segments are the same for SR-MPLS and SRv6;
`show isis repair-list` shows them as labels or SIDs. The view starts
with the same SPF state as `show isis spf` and covers the single-topology
(MT 0) graph.

```
r1> show isis ti-lfa
TI-LFA: enabled (sr-mpls: on, srv6: off)
SPF stats:
  L1: never run, inflight=false, pending=false
  L2: last 47.161s ago, took 564μs, inflight=false, pending=false
      ti-lfa: targets=3 mode=serial workers=1 spf{q=3 pc=3 dedup-saved=0} took 239μs

L2 TI-LFA repair paths:
  Destination r4 (vertex 4)
    [0] first-hop r3 (vertex 2, link_id 3)
        segments:
          NodeSid(r3)
          AdjSid(r3, r4)
```

JSON: `{ levels: { L2: { destinations: [ … ] } } }`, keyed by level, each
destination `{ vertex_id, name, repair_paths: [ { first_hop_vertex_id,
first_hop_name, first_hop_link_id, segments } ] }`.

### `show isis repair-list [detail]`

The TI-LFA backups installed in the RIB, one row per protected route,
with the primary and repair next hops and the segment list as labels
(SR-MPLS) or SIDs (SRv6):

```
r1> show isis repair-list
Level AFI   Prefix                 Primary via            Repair via             Segments
L2    ipv4  10.0.0.4/32            192.168.12.2           192.168.13.3           [16003, 15002, 16004]
```

`detail` starts with the SPF state and, per route, gives the primary and
repair next hops with their metrics and one line per segment:

```
r1> show isis repair-list detail
TI-LFA: enabled (sr-mpls: on, srv6: off)
SPF stats:
  L1: never run, inflight=false, pending=false
  L2: last 47.196s ago, took 564μs, inflight=false, pending=false
      ti-lfa: targets=3 mode=serial workers=1 spf{q=3 pc=3 dedup-saved=0} took 239μs
L2 ipv4 10.0.0.4/32
  Primary: via 192.168.12.2 (ifindex 2), metric 30
  Repair:  via 192.168.13.3 (ifindex 3), metric 31
    NodeSID 16003
    AdjSID 15002
    PrefixSID 16004
```

The last SR-MPLS segment, `PrefixSID`, is the destination's own
Prefix-SID closing the stack. The repair segments before it are named by
position: the first `NodeSID` (`End` for SRv6), the rest `AdjSID`
(`End.X`). The repair metric is the primary's plus one, the metric the
backup is installed with.

JSON: `{ routes: [ { level, family, prefix, primary_nexthop,
primary_ifindex, primary_metric, repair_nexthop, repair_ifindex,
repair_metric, segments: [ { kind, value } ] } ] }`.

### `show isis egress-protection`

The Mirror-SID egress-protection state: locally-configured protected
locators and whether they are advertised, plus the Mirror-SID /
context-label advertisements received from protector peers. With nothing
configured or received it prints
`No egress-protection entries configured or received`. See
[Egress Protection (Mirror SID)](ch-07-08-isis-egress-protection.md).

JSON: `{ local, received_mirror_sids, received_context_labels }`, with
`local` of `{ protected_locator, sid, dataplane, via_vrf, advertised }`,
`received_mirror_sids` of `{ protector, mirror_sid, protected_locator }`,
and `received_context_labels` of `{ protector, context_label,
protected_fec }`.

## Area Proxy

### `show isis area-proxy`

The Area Proxy state (RFC 9666). Without `area-proxy` configured it shows
only that participation is disabled:

```
r1> show isis area-proxy
IS-IS Area Proxy (RFC 9666)
Participation:   disabled
```

When enabled it adds the candidacy (priority and proxy system ID), the
elected Area Leader, readiness (how many inside routers advertise the
Area Proxy TLV), the Proxy System ID, and, when they apply, whether this
router advertises the Proxy System Identifier, the proxy LSP it
originates, the outside circuits and the Area SID. See
[Area Proxy](ch-07-12-isis-area-proxy.md#verifying) for full examples.

JSON: `{ enabled, candidate, proxy_system_id, priority, leader,
leader_priority, self_is_leader, ready, inside_routers, ready_routers,
advertising_proxy_system_id, originating_proxy_lsp, proxy_lsp_fragments,
proxy_lsp_seq_number, outside_circuits, area_sid_prefix,
area_sid_index }`, also when disabled. `leader` is a system ID, where the
text view shows the hostname.

## Segment Routing — Flexible Algorithm

### `show isis flex-algo [<128-255>]`

The Flexible Algorithm state (RFC 9350): the locally-configured
algorithms and their SRv6 locator bindings, then per level which
definition won for each algorithm (RFC 9350 §5.3) — its originator,
priority, and maximum link loss if it carries one — and whether this
router participates, or why not; then the definitions and SR-Algorithm
lists received from peers. See
[Flexible Algorithm (Flex-Algo)](ch-07-11-isis-flexalgo.md) for the
configuration side and the healthy-output signatures.

```
r1> show isis flex-algo
Area 49.0001:

Local Flex-Algorithms:
  Algo  Metric                 Priority Adv FRR       Constraints
  128   igp                    -        yes on        -

Level-2 definition selection:
  Algo 128: definition from r4 (0000.0000.0004), priority 128; participating

Level-2:
  Peer FADs:
    r2 (0000.0000.0002): algo 128 priority 128 metric-type 0 calc-type 0
    r3 (0000.0000.0003): algo 128 priority 128 metric-type 0 calc-type 0
    r4 (0000.0000.0004): algo 128 priority 128 metric-type 0 calc-type 0
  Peer SR-Algorithm Participation:
    r2 (0000.0000.0002): [0, 128]
    r3 (0000.0000.0003): [0, 128]
    r4 (0000.0000.0004): [0, 128]
```

Adding an algorithm ID gives a compact view: the local definition row
and, per level, the peers that participate in the algorithm.

```
r1> show isis flex-algo 128
Area 49.0001:

Local Flex-Algorithm 128:
  Algo  Metric                 Priority Adv FRR       Constraints
  128   igp                    -        yes on        -

L2 peers participating in algorithm 128:
  r2 (0000.0000.0002)
  r3 (0000.0000.0003)
  r4 (0000.0000.0004)
```

JSON: `{ area, local_algorithms, local_srv6_locators, selection,
levels }`. With an algorithm ID, `-j` returns the same whole-view object.

### `show isis flex-algo <128-255> { route | topology | spf | graph | repair-list }`

The per-algorithm versions of `show isis route`, `topology`, `spf`,
`graph` and `repair-list`, which remain algorithm-0 views: the
algorithm's routing table, SPF trees, per-destination SPF results,
pruned link-state graph, and TI-LFA repair list.

```
r1> show isis flex-algo 128 route
Area 49.0001:

Level-2 Algorithm 128:
  Prefix               Metric   Nexthop          Interface    Label
  10.0.0.2/32          20       192.168.12.2     r1-r2        16102
  10.0.0.3/32          25       192.168.13.3     r1-r3        16103
  10.0.0.4/32          30       192.168.12.2     r1-r2        16104
```

An algorithm with an SRv6 locator adds a `Level-N Algorithm <n> (SRv6):`
table of locators. `show isis flex-algo route` without an ID lists every
algorithm's routes. The older spelling
`show isis flex-algo route algorithm <id>` still parses but is a
deprecated alias kept for existing scripts.

The graph view ends with `Pruned links:`, one line per directed link the
definition leaves out and why — `affinity`, or `link loss … exceeds …`.
The list appears only while this router participates in the algorithm.

JSON:

- `route`: `{ area, groups: [ { level, algorithm, family, routes } ] }`,
  with `family` `ipv4` or `srv6` and routes `{ prefix, metric, label,
  nexthops: [ { address, interface } ] }`.
- `topology`, `spf` and `repair-list`: the shapes of `show isis
  topology`, `show isis spf` and `show isis repair-list`; the SPF
  topology key reads `"L2 (algorithm 128)"`.
- `graph`: the shape of `show isis graph`, with `level` reading
  `"L2 algo 128"` and a `pruned` list of `{ from, to, reason, loss,
  max_link_loss }` when links are pruned.

## Graceful Restart

### `show isis graceful-restart`

The RFC 5306 Graceful Restart state: the helper and restarter
configuration, then per adjacency its state, whether this router is
helping it restart, its restart count, the RR / RA / SA bits of the
last Restart TLV it sent, and the remaining grace time.

```
r1> show isis graceful-restart
Graceful Restart (RFC 5306) — helper mode
Helper:    enabled (config)
Restarter: disabled (config)

L  System Id           Interface    State          Helper   Restarts RR RA SA Remaining
2  0000.0000.0002      r1-r2        Up             -        0        0  0  0  -
2  0000.0000.0003      r1-r3        Up             -        0        0  0  0  -
```

JSON: an array of `{ level, system_id, interface, state, helper_active,
restart_count, rr, ra, sa, remaining_time, restarting_neighbor }`;
`remaining_time` and `restarting_neighbor` only when set. The helper and
restarter configuration is in the text view only.

### `show isis checkpoint`

The on-disk graceful-restart checkpoint: its path, format version, write
time, system ID, area addresses and IS type, grace period, the
self-originated LSPs, and the adjacencies captured at checkpoint time —
what a restart would replay. Without a checkpoint file:

```
r1> show isis checkpoint
Checkpoint path: /var/lib/zebra-rs/checkpoint/isis.cbor
  (no checkpoint: No such file or directory (os error 2))
```

The file is `isis.cbor` under `$ZEBRA_ISIS_CHECKPOINT_DIR`, by default
`/var/lib/zebra-rs/checkpoint`.

JSON: `{ format_version, written_at, grace_period_secs, sys_id,
area_addrs, is_type, levels: [ { level, self_lsps } ], adjacencies }`,
or `{ path, error }` when there is no readable checkpoint.
