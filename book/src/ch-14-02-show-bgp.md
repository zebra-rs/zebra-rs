# BGP

The `show bgp` family reports BGP's Loc-RIB for every address family,
neighbor state, the per-peer Adj-RIB-In/Out, update-group internals, and
the MUP controller. Every command honors the `-j` / `--json` flag.

A bare `show bgp` is shorthand for `show bgp ipv4` — the IPv4 unicast
Loc-RIB. All the route-table views share one layout and status legend:

```
Status codes:  s suppressed, d damped, h history, * valid, > best,
               = multipath, i internal, S Stale, R Removed
Origin codes:  i - IGP, e - EGP, ? - incomplete

    Network        Next Hop   Metric LocPrf Weight Path
 *> 10.0.0.0/24    192.0.2.1                     0 65000 i
```

`*>` marks a valid best path; `i` in the leading code column marks an
iBGP-learned route.

## Per-family Loc-RIB

### `show bgp [<addr>|<prefix>]` (IPv4 unicast)

The IPv4 unicast table. Append a `<prefix>` for an exact match, or a
bare `<addr>` for a longest-prefix-match lookup.

### `show bgp ipv4 [<addr>|<prefix>|summary]`

The explicit IPv4 unicast form. `summary` renders only the IPv4-unicast
neighbor section (see [`show bgp summary`](#show-bgp-summary)).

### `show bgp ipv4 <prefix> longer-prefix`

Every route equal to or more specific than `<prefix>` (a CIDR-subtree
match) — handy for auditing what a peer is advertising under an
aggregate.

### `show bgp ipv6 …`

The IPv6 unicast twins of all the IPv4 forms above: `show bgp ipv6`,
`show bgp ipv6 <addr>|<prefix>|summary`, and `show bgp ipv6 <prefix>
longer-prefix`.

JSON (all unicast forms): an array of route objects with `prefix`,
`valid`, `best`, `internal`, `route_type` (`iBGP`/`eBGP`), `next_hop`,
`metric`, `local_pref`, `weight`, `as_path`, and `origin`. The `summary`
forms instead return the summary object documented below.

### `show bgp vpnv4 [<addr>|<prefix>|summary]` / `show bgp vpnv6 …`

The L3VPN Loc-RIB (SAFI 128), grouped by Route Distinguisher. Each entry
shows its RD, the per-route extended communities (route-targets), and
the VPN label. See [L3VPN and Per-VRF Labels](ch-02-04-bgp-l3vpn.md).

```
r1> show bgp vpnv4
Route Distinguisher: 65000:100
 *> 10.0.0.0/24   192.0.2.2                     0 65001 i
      RT:65001:100 label=1001
```

JSON: an array of route objects that add `route_distinguisher`, `label`,
`extended_community`, and `path_id` to the common attributes. (VPNv6
reuses the same shape; `prefix` is a string and family-agnostic.)

### `show bgp labeled-unicast`

The Labeled-Unicast Loc-RIB (SAFI 4), IPv4 and IPv6, with a per-prefix
MPLS label column.

JSON: an array with `family` (`ipv4`/`ipv6`), `prefix`, `label`, plus the
common route attributes.

### `show bgp evpn [route-type <type>]`

The EVPN Loc-RIB (L2VPN, SAFI 70), grouped by RD. `route-type` filters
to one NLRI type: `ethernet-ad`, `macip`, `multicast`,
`ethernet-segment`, `prefix`, `smet`, `igmp-join-sync`,
`igmp-leave-sync`, `per-region-imet`, `s-pmsi`, or `leaf`. See the EVPN
chapters starting at [EVPN Type-5](ch-02-06-bgp-evpn-type5.md).

- `show bgp evpn summary` — the EVPN neighbor section only.
- `show bgp evpn ethernet-segment` — locally-configured Ethernet
  Segments (RFC 7432): ESI, redundancy mode, member VTEPs, DF algorithm,
  and the elected Designated Forwarder.

JSON: an array of EVPN route objects (`route_distinguisher`,
`route_type`, `prefix`, common attrs, `extended_communities`);
`ethernet-segment` returns an array of segment objects.

### `show bgp flowspec [ipv6]`

The Flow Specification Loc-RIB (RFC 8955, SAFI 133): match criteria,
action, validation state, and the originating peer. Add `ipv6` for the
IPv6 family.

JSON: an array of `{ family, match, action, from, valid, validity }`.

### `show bgp sr-policy [ipv6]`

The SR Policy Loc-RIB (SAFI 73): each policy's color and endpoint, its
candidate paths (origin, preference, binding-SID), and segment lists.
Add `ipv6` for the IPv6 family.

JSON: an array of policy objects with `color`, `endpoint`, and a
`candidate_paths` array (`protocol_origin`, `preference`, `valid`,
`active`, `binding_sid`, `segment_lists`).

### `show bgp link-state`

The BGP Link-State Loc-RIB (RFC 9552, SAFI 71): one line per NLRI
(node / link / prefix descriptor), the source peer, and a digest of the
link-state TLVs.

JSON: an array of `{ nlri_type, nlri, neighbor, best }`.

### `show bgp mup [summary]`

The Mobile User Plane Loc-RIB (SAFI 85): Direct-Segment, ISD, and
Type-1/Type-2 Session-Transformed routes. `summary` shows the
IPv4-MUP / IPv6-MUP neighbor sections. On an interwork node, each ST route
resolved to its segment prints a `resolved … -> End.DT46 <sid> (via
[DSD|ISD]…)` line — ST2→DSD as `resolved <ep> -> …` (matched by
Direct-segment id), ST1→ISD as `resolved <ue> (endpoint <ep>) -> …` (the gNB
endpoint is the lookup key, the UE prefix the forwarded destination); the
per-VRF `show bgp vrf <name> mup` shows the same for a forwarding VRF. See
[Mobile User Plane (MUP)](ch-02-35-bgp-mup.md).

### `show bgp mup-c [session|association]`

The MUP Controller (MUP-C): admin state and PFCP listen address;
`session` lists learned PFCP sessions (SEID, UE address, TEID, QFI);
`association` lists PFCP CP/UP associations. See
[Mobile User Plane (MUP)](ch-02-35-bgp-mup.md).

JSON: an array of MUP route objects; `mup-c` returns a controller object
or an array of session / association objects.

## Neighbor state

### `show bgp summary`

One section per AFI/SAFI configured on at least one neighbor, each
listing peer version, AS, message counters, uptime, FSM state, and
prefix counts received/sent.

```
r1> show bgp summary
IPv4 Unicast Summary:
BGP router identifier 192.0.2.1, local AS 65000, VRF default
Neighbor    V    AS  MsgRcvd MsgSent Up/Down     State    PfxRcd/Snt
192.0.2.2   4 65001       42      40 00:05:00 Established       42/10
```

JSON: `{ router_id, local_as, afi_safis: [ { afi_safi, peers: [ … ] } ] }`.

### `show bgp neighbor [<addr>|<name>]`

Full per-neighbor detail — FSM state, negotiated capabilities, timers,
and message counters. With no argument it lists every neighbor,
including interface-keyed IPv6 unnumbered peers (which are addressed by
their interface `<name>`; see
[IPv6 Unnumbered](ch-02-27-bgp-unnumbered.md)).

JSON: a single neighbor object, or an array of them.

### Per-neighbor Adj-RIB views

- `show bgp neighbor <addr> advertised-routes [ipv6|vpnv4|evpn]` — the
  Adj-RIB-Out (what this peer is being sent, after outbound policy).
- `show bgp neighbor <addr> received-routes [ipv6|vpnv4|evpn]` — the
  Adj-RIB-In (what this peer sent, before inbound policy).
- `show bgp neighbor <addr> rtcv4` — the IPv4/IPv6 Route Target
  Constraints (RFC 4684) exchanged with the peer. See
  [Route Target Constraint](ch-02-07-bgp-rtc.md).

The family keyword (default IPv4 unicast) selects which Adj-RIB table to
render. JSON mirrors the corresponding Loc-RIB family shape
(unicast / VPNv4 / EVPN); `rtcv4` returns
`{ neighbor, ipv4: [...], ipv6: [...] }`.

## Configuration and internals

### `show bgp neighbor-group [<name>]`

Neighbor-group inheritance state — with no argument, a table of every
group with its remote-AS and member count; with a `<name>`, the group's
members and inherited knobs. See
[Neighbor Groups](ch-02-26-bgp-neighbor-group.md).

JSON: an array of group rows, or one group detail object.

### `show bgp update-group [<id>]`

The IOS-XR-style update-groups: peers that share an identical outbound
policy and capability signature are coalesced into one group so an
update is formatted once and fanned out. With no argument, a summary
table; with an `<id>`, the group's signature, members, and counters.

```
r1> show bgp update-group
ID            Members Type  AS    Policy-out     Updates
ipv4-unicast.0      3 ebgp  65001 customer-out   42 / 40

1 group, 3 members.
```

JSON: `{ groups: [ … ] }`.

### `show bgp attributes`

The shared path-attribute store: total / active entry counts (split
across the main table and the sharded table), and each interned
attribute set with its refcount. A diagnostic for memory and attribute
sharing. See [RIB Sharding](ch-02-31-bgp-rib-sharding.md).

JSON: `{ total_entries, active_entries, main_entries, shard_entries,
attributes: [ { refcnt, store, attr } ] }`.

## Per-VRF BGP

### `show bgp vrf [<name>] [summary|neighbor|ipv4|ipv6|mup]`

With no name, a table of every BGP VRF — its RD, per-VRF label,
table-id, peer count, and running state. With a `<name>` and a
subcommand, the request is forwarded to that VRF's BGP task and rendered
by the matching handler above (so `show bgp vrf blue summary` mirrors
`show bgp summary` for VRF `blue`).

```
r1> show bgp vrf
Name  RD          Label  Table-ID  Peers  State
blue  65000:100   1001   256       2      running
red   65000:200   1002   257       1      running
```

JSON (the no-name list): an array of
`{ name, rd, label, table_id, peers, running }`. The per-VRF
subcommands return their sibling's JSON shape.
