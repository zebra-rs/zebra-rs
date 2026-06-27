# IS-IS

The `show isis` family reports adjacencies, the link-state database, the
per-level SPF results and routing table, DIS election, and Fast ReRoute
(TI-LFA) state. Every command honors `-j` / `--json`, and each accepts a
`vrf <name>` selector that mirrors the non-VRF sibling (see the
[overview](ch-14-00-show-overview.md)).

Most views are organized per **level** (L1 / L2) and, where relevant,
per address family (IPv4 / IPv6). See the protocol chapters for
configuration: [IS-IS](ch-07-00-isis.md).

## Overview

### `show isis`

Basic instance information (a banner today; JSON `{}`). Use
`show isis summary` for the operational digest.

### `show isis summary`

The area LSP-MTU, the L1 area-password / L2 domain-password
authentication state, and the configured SRv6 locator's status.

```
r1> show isis summary
LSP MTU: 1492 bytes
Area-password (L1):   mode MD5, key-id 0
Domain-password (L2): mode MD5, key-id 0

SRv6 Locator:
Name    Prefix             Behavior  Status
LOC_N1  2001:db8:a:1::/64  Classic   Up
```

JSON: `{ lsp_mtu, area_password, domain_password, srv6_locator }`.

### `show isis hostname`

The dynamic-hostname mappings (LSP TLV 137) — system-ID → hostname —
learned across the domain, per level.

JSON: a per-level mapping of system-ID to hostname.

## Adjacencies and interfaces

### `show isis neighbor [detail]`

The IS-IS adjacencies per interface and level: neighbor system-ID,
state, and uptime. `detail` adds holdtime, the DIS/DR flag, circuit ID,
and extended reachability.

```
r1> show isis neighbor
Interface  Level  Neighbor-ID     State  Uptime
eth0       1      aaaa.bbbb.cccc  Up     5m23s
eth0       2      aaaa.bbbb.cccd  Up     2h14m
```

JSON: an array of per-adjacency objects; `detail` returns the expanded
form.

### `show isis interface [detail]`

The IS-IS link configuration and state: circuit type, metric, hello
timers, and network type. `detail` adds authentication state, the
adjacency list, and PDU counters.

JSON: an array of per-interface objects.

### `show isis dis statistics` / `show isis dis history`

DIS (Designated IS) election diagnostics. `statistics` shows, per
circuit and level, the current DIS and the number of elections;
`history` is the timestamped log of past DIS transitions.

JSON: per-interface/level election objects (`statistics`); a timestamped
transition list (`history`).

## Database

### `show isis database [detail]`

The LSDB per level. The summary lists each LSP-ID with its PDU length,
sequence number, checksum, remaining holdtime, and the ATT/P/OL bits
(with a fragment summary for multi-fragment originators). `detail`
expands each LSP's full TLV content.

```
r1> show isis database
L1 Link State Database:
LSP ID                PduLen  SeqNumber   Chksum  Holdtime  ATT/P/OL
aaaa.bbbb.cccc.00-00 *  1200  0x00000001  0x9a5b      3600  0/0/0
```

JSON: an object with `level_1` / `level_2` arrays of LSP-summary objects
(`lsp_id`, `seq_number`, `checksum`, `holdtime`, `att_bit`, `p_bit`,
`ol_bit`, …); `detail` serializes the full LSP bodies.

## Routes, topology and SPF

### `show isis route [detail]`

The IS-IS routing table per level and family, with metric and nexthops.
`detail` adds the Prefix-SID and any TI-LFA backup path (with the
imposed label stack / SRv6 segments) per route.

```
r1> show isis route
L1 192.0.2.0/24 [metric 20]
  via 192.0.2.1, eth0, Router2
```

JSON: `{ level_1: [ … ], level_2: [ … ] }`, each route with `prefix`,
`metric`, and a `nexthops` array (`address`, `interface`, `label`,
`implicit_null`).

### `show isis topology`

The per-level, per-AFI SPF tree — vertices and reachable prefixes with
their metric, nexthop, and parent — without the RIB tables that
`show isis route` adds.

JSON: `{ area, levels: [ { level, ipv4, ipv6 } ] }`.

### `show isis spf [detail]`

The SPF computation results per topology: the TI-LFA enable state, the
per-level SPF timing stats, and each destination's cost, nexthops, and
path vectors. `detail` adds the full per-destination path breakdown.

JSON: `{ ti_lfa_enabled, sr_mpls_enabled, sr_srv6_enabled, topologies }`.

### `show isis graph`

The SPF graph per level — nodes with their outgoing and incoming costed
links.

JSON: an array of `{ level, nodes: [ { id, name, sys_id, olinks,
ilinks } ] }`.

## Fast ReRoute (TI-LFA)

### `show isis fast-reroute summary`

Per-level protection tallies for IPv4 and IPv6 separately: total
prefixes, protected vs. unprotected, and the repair complexity breakdown
(trivial / 1-segment / N-segment). See
[Fast Failover: TI-LFA + BFD](ch-12-00-nexthop-protect.md).

```
r1> show isis fast-reroute summary
Level-1 IPv4:
  Total prefixes: 100
  Protected:       80  (trivial 20, 1-seg 50, N-seg 10)
  Unprotected:     20
```

JSON: `{ area, levels: [ { level, ipv4, ipv6 } ] }`.

### `show isis fast-reroute prefix <A.B.C.D/M> detail`

The TI-LFA protection detail for one IPv4 prefix — per-nexthop backup
path with its P/Q nodes and segment composition.

JSON: `{ prefix, found, entries: [ { level, metric, protected,
nexthops } ] }`.

### `show isis ti-lfa`

The graph-level TI-LFA repair paths from the last SPF, per destination
and level: the repair first-hop and the segment list (Node-SID /
Adj-SID for SR-MPLS, End / End.X for SRv6).

JSON: `{ levels: { L1: { destinations: [ … ] }, L2: { … } } }`.

### `show isis repair-list [detail]`

The TI-LFA backups installed in the RIB: one row per protected route
(level, family, prefix) with primary and repair nexthops and the segment
list. `detail` breaks out each segment.

JSON: `{ routes: [ { level, family, prefix, primary_nexthop,
repair_nexthop, segments } ] }`.

### `show isis egress-protection`

The Mirror-SID egress-protection state: locally-configured protected
locators and their advertised status, plus the Mirror-SID /
context-label advertisements received from protector peers. See
[Egress Protection (Mirror SID)](ch-07-08-isis-egress-protection.md).

JSON: `{ local, received_mirror_sids, received_context_labels }`.

## Segment Routing — Flexible Algorithm

### `show isis flex-algo`

The Flexible Algorithm state (RFC 9350): the locally-configured
algorithms and their SRv6 locator bindings, plus the FADs, algorithms,
and SRv6 locators received from peers, per level.

JSON: `{ area, local_algorithms, local_srv6_locators, levels }`.

### `show isis flex-algo route [algorithm <id>]`

The per-algorithm routing tables — IPv4 (SR-MPLS) and IPv6 (SRv6
locator) — grouped by level and algorithm. Add `algorithm <id>` to
filter to a single algorithm (0–255).

```
r1> show isis flex-algo route algorithm 128
Level-1 Algorithm 128:
  Prefix        Metric  Interface  Nexthop    Label
  192.0.2.0/24      10  eth0       192.0.2.1  16128
```

JSON: `{ area, groups: [ { level, algorithm, family, routes } ] }`.

## Graceful Restart

### `show isis graceful-restart`

The RFC 5306 Graceful Restart state per adjacency: helper/restarter
config, and per-neighbor helper-active state, restart counters, the
RR/RA/SA signaling bits, and remaining grace time.

JSON: an array of per-adjacency objects (`level`, `system_id`,
`interface`, `helper_active`, `rr`, `ra`, `sa`, `remaining_time`, …).

### `show isis checkpoint`

A diagnostic dump of the on-disk graceful-restart checkpoint: format
version, write time, system-ID, grace period, the self-originated LSPs,
and the adjacency state captured at checkpoint time.

JSON: a checkpoint object including the LSP bodies and adjacency records.
