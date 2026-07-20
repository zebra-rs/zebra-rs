# PIM — Protocol Independent Multicast (Sparse Mode)

PIM-SM (RFC 7761) builds explicit multicast distribution trees on top of
whatever unicast routing table already exists — it borrows the unicast
RIB for its Reverse Path Forwarding (RPF) checks rather than running a
topology protocol of its own, which is what "protocol independent"
means. Receivers signal interest with IGMP (IPv4) or MLD (IPv6); the
last-hop router grafts a shared tree toward a Rendezvous Point (RP);
first-hop routers register new sources to the RP; and each router
switches to the shortest-path source tree once traffic is flowing.

zebra-rs implements PIM-SM and PIM-SSM for **both** address families
from one generic engine, so the IPv4 and IPv6 command surfaces are
symmetric. Everything documented for IPv4 under `router pim …` /
`show pim …` has an IPv6 counterpart under `router pim ipv6 …` /
`show pim ipv6 …`; the only differences are the address literals and
that local membership is MLD (RFC 3810) for IPv6 rather than IGMP
(RFC 3376) for IPv4.

Implemented feature set:

- **Any-Source Multicast (ASM)** — shared tree to an RP, PIM Register /
  Register-Stop, and the switch to the source-specific shortest-path
  tree (SPT).
- **Source-Specific Multicast (SSM)** — `232.0.0.0/8` (IPv4) and
  `FF3x::/32` (IPv6), source-specific joins with no RP.
- **RP discovery** — static mappings, the Bootstrap Router (BSR,
  RFC 5059) with the RFC 2362 group-to-RP hash, and — for IPv6 —
  Embedded-RP (RFC 3956).
- **LAN behaviors** — DR election, Assert election, Join suppression and
  Prune override.
- **Per-VRF instances** for both families, and conditional tracing.

Configuration lives under `/router/pim` in the YANG schema. This chapter
walks the operational surface; the sections below use IPv4 syntax and
note the IPv6 form where it differs.

## Enabling PIM on an interface

PIM runs only on interfaces you enable it on. Naming an interface under
`router pim interface` is enough to start Hellos and DR election there:

```
set router pim interface eth0
```

Per-interface knobs:

```
set router pim interface eth0 dr-priority 100
set router pim interface eth0 hello interval 30
set router pim interface eth0 hello holdtime 105
set router pim interface eth0 passive true
```

- `dr-priority` (default `1`) elects the Designated Router on a LAN; the
  highest priority wins, the highest primary address breaks ties. Only
  the DR turns local IGMP/MLD membership into forwarding state and only
  the DR registers directly-connected sources.
- `hello interval` (seconds, `1..18000`, default `30`) is the Hello
  transmit period; `hello holdtime` (`1..65535`) is the neighbor
  liveness the Hello advertises. Changing the interval re-arms the timer
  on a running interface.
- `passive` (default `false`) keeps the interface in the topology (its
  subnet is eligible for RPF and forwarding) but sends and processes no
  PIM packets — useful for a stub LAN with receivers but no PIM peers.

The IPv6 form is identical under `router pim ipv6 interface`. PIMv6
Hellos are sourced from the interface link-local address (RFC 7761
§4.3.1); the router advertises its global addresses in the Hello Address
List so a neighbor can match an RPF nexthop that resolves to one of
them.

## Local membership: IGMP (IPv4) and MLD (IPv6)

A last-hop router learns which groups its directly-connected hosts want
by acting as the IGMP (IPv4) or MLD (IPv6) querier. Enable it per
interface:

```
set router pim interface eth0 igmp enabled true
set router pim interface eth0 igmp version 3
set router pim interface eth0 igmp query-interval 125
set router pim interface eth0 igmp query-max-response-time 10
```

- `version` — IGMP `2..3` (default `3`); the IPv6 `mld version` is `1..2`
  (default `2`). Version 3 / MLDv2 carry source lists, which is what SSM
  requires.
- `query-interval` (seconds, `1..1800`, default `125`) is the General
  Query period.
- `query-max-response-time` (seconds, `1..25`, default `10`) is the
  maximum response time advertised in queries.

For IPv6 the container is `mld` instead of `igmp`:

```
set router pim ipv6 interface eth0 mld enabled true
set router pim ipv6 interface eth0 mld version 2
```

IGMPv3 EXCLUDE{} / MLDv2 EXCLUDE{} reports create any-source `(*,G)`
membership (ASM); an INCLUDE report with a source list creates
source-specific `(S,G)` membership (SSM).

## Rendezvous Points (ASM)

Any-Source Multicast needs a Rendezvous Point — the meeting place where a
new source (via Register) and the shared tree (from receivers) first
come together. zebra-rs resolves the RP for a group in a fixed
precedence order:

1. an explicit **static** mapping,
2. **Embedded-RP** (IPv6 only — the group carries its own RP),
3. a **BSR**-learned mapping.

### Static RP

Map a group range to an RP address. With no `group`, the RP serves the
whole multicast range:

```
set router pim rp static 10.0.0.1
set router pim rp static 10.0.0.1 group 239.1.0.0/16
```

The default group is `224.0.0.0/4` (IPv4) / `ff00::/8` (IPv6). Configure
the same RP address on every router in the domain. The IPv6 form:

```
set router pim ipv6 rp static 2001:db8::1
set router pim ipv6 rp static 2001:db8::1 group ff3e::/32
```

### Bootstrap Router (BSR, RFC 5059)

Instead of configuring the RP set on every router, one or more Candidate
BSRs elect a domain BSR, Candidate RPs advertise themselves to it, and
the elected BSR floods the collected RP set in Bootstrap messages so
every router learns the same mapping.

Run as a Candidate BSR:

```
set router pim bsr candidate-bsr address 10.0.0.2
set router pim bsr candidate-bsr priority 100
```

Advertise this router as a Candidate RP:

```
set router pim bsr candidate-rp address 10.0.0.2
set router pim bsr candidate-rp group 239.0.0.0/8
set router pim bsr candidate-rp priority 192
```

- `candidate-bsr priority` (default `64`) — highest wins the BSR
  election, highest address breaks ties.
- `candidate-rp priority` (default `192`) — **lowest** is preferred.
- `candidate-rp group` (default `224.0.0.0/4` / `ff00::/8`) is the range
  this RP serves.

When several Candidate RPs cover a group with the same longest-match
range and the same priority, all routers pick the same one using the
RFC 2362 group-to-RP hash, so the whole domain agrees. The IPv6 form
lives under `router pim ipv6 bsr` and takes IPv6 addresses.

### Embedded-RP (IPv6 only, RFC 3956)

An IPv6 group in `ff70::/12` encodes its own RP address in its bits. No
configuration is needed anywhere — every router derives the same RP
straight from the group. For example the group
`ff7e:240:2001:db8:22::9` embeds RP `2001:db8:22::2`; the router that
owns that address becomes the RP purely by derivation. Embedded-RP sits
between static and BSR in the precedence order.

## Source-Specific Multicast (SSM)

SSM needs no RP: a receiver joins a specific `(source, group)` with an
IGMPv3 / MLDv2 source-specific report, the last-hop router builds the
`(S,G)` shortest-path tree straight toward the source, and the first-hop
router forwards natively. SSM groups are `232.0.0.0/8` (IPv4, RFC 4607)
and `FF3x::/32` (IPv6, any scope). No PIM configuration beyond enabling
PIM and membership on the relevant interfaces is required — the SSM range
is recognized automatically and never uses an RP.

## Per-VRF instances

Every configuration surface above is available inside a VRF, running a
fully isolated PIM instance — sockets bound into the VRF, the kernel
multicast table selected per VRF, and membership / tree state scoped to
it. Prefix the path with `vrf <name>`:

```
set router pim vrf blue interface eth1 dr-priority 1
set router pim vrf blue interface eth2 igmp enabled true
set router pim vrf blue rp static 10.0.0.1
set router pim vrf blue ipv6 interface eth1 mld enabled true
set router pim vrf blue ipv6 rp static 2001:db8::1
```

Multicast in one VRF neither sees nor disturbs the default table or any
other VRF.

## Conditional tracing

By default PIM emits no informational logs. `router pim tracing` turns
them on per category at runtime — no restart, and one block drives every
PIM instance (default IPv4, default-table IPv6, and per-VRF children):

```
set router pim tracing all
set router pim tracing neighbor
set router pim tracing register
```

Categories: `all` (master switch), `neighbor`, `interface`, `membership`
(IGMP/MLD), `tib` ((S,G)/(*,G) tree state), `join-prune`, `assert`,
`register`, `bsr`, `mroute` (kernel MRT/MIF/MFC datapath), and `event`
(instance lifecycle). Each is a presence toggle — name it to enable,
delete it to disable. This mirrors the IS-IS / OSPF / BGP `tracing`
model; see also [Protocol-Specific Logging](ch-03-03-protocol-logging.md).

## Show commands

The show surface is symmetric between the families: every `show pim …`
command has a `show pim ipv6 …` counterpart, and both take a
`vrf <name>` selector for a per-VRF instance.

| Command | Shows |
|---|---|
| `show pim` | Instance summary (configured / enabled interfaces, neighbor count) |
| `show pim interface` | Per-interface state: address, DR, DR priority, Hello interval, neighbors |
| `show pim neighbor` | Discovered PIM neighbors per interface |
| `show pim upstream` | `(*,G)` / `(S,G)` tree entries: RPF interface, RPF neighbor, Join state, Register state |
| `show pim rp-info` | Group-to-RP mappings (static and BSR-learned) and whether this router is the RP |
| `show pim bsr` | Bootstrap Router election state and the learned RP set |
| `show pim assert` | Assert election winner / loser per interface |
| `show mroute` | The multicast routing table (`(S,G)` / `(*,G)`, IIF, OIF list, flags) |
| `show igmp interface` | IGMP querier state per interface |
| `show igmp groups` | Learned IGMP group (and source) memberships |

For IPv6, the multicast routing table moves under the `pim` container as
`show pim ipv6 mroute` (there is no top-level `show mroute ipv6`), and
membership is MLD:

```
show pim ipv6
show pim ipv6 interface
show pim ipv6 neighbor
show pim ipv6 upstream
show pim ipv6 rp-info
show pim ipv6 bsr
show pim ipv6 assert
show pim ipv6 mroute
show pim ipv6 mld interface
show pim ipv6 mld groups
```

Per-VRF, insert `vrf <name>` after `pim`, for example:

```
show pim vrf blue neighbor
show pim vrf blue upstream
show mroute vrf blue
show pim vrf blue ipv6 mroute
```

Note that the kernel forwarding cache itself is visible with the
standard iproute2 tools — `ip mroute show` for IPv4 and
`ip -6 mroute show` for IPv6 (add `table all` to see a VRF's table) —
which is what the `show … mroute` command output is derived from.
