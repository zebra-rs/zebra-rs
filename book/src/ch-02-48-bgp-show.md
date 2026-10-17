# BGP Show Commands

The `show bgp` family reports BGP's Loc-RIB for every address family,
neighbor state, the per-peer Adj-RIB-In/Out, update-group internals,
EVPN service state, and the MUP controller. Every command honors the
`-j` / `--json` flag; see
[Operational Show Commands](ch-06-03-show-commands.md) for how to run a
show command and request JSON.

A bare `show bgp` is shorthand for `show bgp ipv4` — the IPv4 unicast
Loc-RIB. All the route-table views share one layout and status legend:

```
Status codes:  s suppressed, d damped, h history, u unsorted,
               * valid, > best, = multipath,
               i internal, r RIB-failure, S Stale, R Removed
Nexthop codes: @NNN nexthop's vrf id, < announce-nh-self
Origin codes:  i - IGP, e - EGP, ? - incomplete
RPKI validation codes: V valid, I invalid, N Not found

    Network            Next Hop            Metric LocPrf Weight Path
 *>  10.0.0.0/24        192.0.2.1                              0 65001 i
 *>i 10.1.0.0/24        192.0.2.9                0    100      0 i
```

`*>` marks a valid best path (`*=` a multipath), `i` after it marks an
iBGP-learned route, and a leading `S` a stale one.

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

`show bgp evpn summary` shows the EVPN neighbor section only. The EVPN
service views (`ethernet-segment`, `vpws`, `etree`) are under
[EVPN services](#evpn-services).

JSON: an array of EVPN route objects (`route_distinguisher`,
`route_type`, `prefix`, common attrs, `extended_communities`).

### `show bgp flowspec [ipv6]`

The Flow Specification Loc-RIB (RFC 8955, SAFI 133): match criteria,
action, validation state, and the originating peer. Add `ipv6` for the
IPv6 family.

JSON: an array of `{ family, match, action, from, valid, validity }`.

### `show bgp sr-policy [ipv6]`

The SR Policy Loc-RIB (SAFI 73): each policy's color and endpoint, its
candidate paths (origin, preference, binding-SID), and segment lists.
Add `ipv6` for the IPv6 family.

A headend claims a policy's SR-MPLS Binding-SID in its SRLB before
installing the Binding-SID's ILM (RFC 9256 §6.2), and the policy shows
the label's state:

```
 SR Policy color 100 endpoint 192.168.12.2
  Binding-SID label 16100: unavailable (outside the SRLB 15000-15999)
  * candidate-path origin bgp disc 1 pref 100 prio 128 [valid]
```

- `held`: the policy has the label; its ILM is installed once the
  endpoint resolves.
- `waiting`: an IGP's dynamic Adjacency-SID held the label and is being
  moved off it.
- `unavailable`: outside the SRLB, held by a configured Adjacency-SID,
  another SR Policy's Binding-SID, or no SRLB. The path stays active with
  no Binding-SID ILM, so steering uses its inline segment list. A path with
  the Specified-BSID-only flag is instead invalid, shown as `[invalid:
  Binding-SID unavailable]`, and the next path is selected.

JSON: an array of policy objects with `color`, `endpoint`,
`binding_sid_label` (`label`, `state`: `held`/`waiting`/`unavailable`,
`reason`), and a `candidate_paths` array (`protocol_origin`, `preference`,
`valid`, `binding_sid_unavailable`, `active`, `binding_sid`,
`segment_lists`).

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

## EVPN services

These views report EVPN state beyond the Loc-RIB: the VNIs this node
serves, its Ethernet Segments, VPWS and E-Tree services, and duplicate
address detection. The two `show evpn` commands sit outside `show bgp`
but are answered by BGP, which owns the EVPN state.

### `show evpn vni all`

Every VNI this node takes part in, from any source: a kernel VXLAN
device, a configured MPLS EVI, a VRF's symmetric-IRB L3VNI, or remote
IMET (Type-3) state. The header gives the advertise-all-vni flag, the
BUM flooding mechanism, and the L2 and L3 VNI counts.

```
r1> show evpn vni all
Advertise All VNI flag: Enabled
BUM flooding: Head-end replication
Number of L2 VNIs: 2
Number of L3 VNIs: 1
Flags: * - Kernel VXLAN device
  VNI        Type Local VTEP                RD                     Import/Export RT  #MACs(loc)  #MACs(rem) #Remote VTEPs  Tenant VRF
* 10         L2   192.168.0.1               192.168.0.1:10         65001:10                   2           2             1  default
  20         L2   -                         192.168.0.1:20         65001:20                   0           1             1  default
* 4001       L3   2001:db8:ff::1            192.168.0.1:4001       65001:4001                 0           0             0  cust1
```

- `*` marks a VNI with a kernel VXLAN device. VNI 20 above has none: it
  is known only from a remote IMET route, so it has no local VTEP.
- `Type` is `L3` when a VRF uses the VNI as its L3VNI, else `L2`.
- `RD` is the auto-derived `router-id:vni`, and `-` while the router-id
  is unset or the VNI does not fit in 16 bits.
- `Import/Export RT` is the auto-derived `as:vni` exactly as advertised:
  a 4-byte AS is cut to its low 16 bits.
- `BUM flooding` is `Head-end replication`, `Assisted replication
  (replicator)` or `(leaf)`, `SR-MPLS P2MP replication tree`, or `SRv6
  P2MP replication tree`.

Per-MAC state is in
[`show l2 mac table`](ch-14-01-show-system-rib.md#show-l2-mac-table).

JSON: `{ advertise_all_vni, bum_flooding, num_l2_vnis, num_l3_vnis,
vnis: [ { vni, type, kernel, local_vtep, rd, route_target, local_macs,
remote_macs, remote_vteps, tenant_vrf } ] }`. `local_vtep` and `rd` are
omitted when absent.

### `show bgp evpn ethernet-segment`

The locally-configured Ethernet Segments (RFC 7432): ESI, redundancy
mode, interface, ES-Import RT, the ESI label (MPLS), member VTEPs, the
DF algorithm, and the elected Designated Forwarder. See
[EVPN Single-Active Multihoming](ch-02-45-bgp-evpn-single-active.md).

JSON: an array of segment objects.

### `show bgp evpn vpws`

Each EVPN VPWS (E-Line, RFC 8214) service: its EVI, local and remote
service IDs, the attachment circuit (interface, VLAN, MTU), the local and
remote endpoint for its encapsulation (SRv6 SIDs, VXLAN VNI and VTEP, or
MPLS labels), the Ethernet Segment and role when multihomed, and its
state.

```
r1> show bgp evpn vpws
VPWS service: eline1
  EVI: 100
  Service ID: local 101, remote 102
  Interface: ce1
  Local SID (End.DX2): fcbb:bbbb:1:40::
  Remote SID: fcbb:bbbb:2:40::
  State: up
```

The state is `partial-config`, `pending`, `advertised`, `up`,
`mtu-mismatch` or `vni-conflict`. See
[EVPN VPWS](ch-02-38-bgp-evpn-vpws.md#show-command) for each line and
state.

JSON: an array of service objects with `name`, `evi`,
`local_service_id`, `remote_service_id`, `interface`, `vlan`, `mtu`, the
endpoint fields (`local_sid` / `remote_sid`, `local_vni` / `remote_vtep`
/ `remote_vni`, `local_label` / `remote_label`, `remote_pe`), the segment
fields (`ethernet_segment`, `esi`, `redundancy_mode`, `role`,
`designated_forwarder`), and `state`.

### `show bgp evpn etree`

E-Tree (RFC 8317) state: each leaf attachment circuit with its EVIs and
local MACs, the remote MACs behind a leaf per EVI, the leaf label (MPLS)
or leaf argument (SRv6) of this PE and each remote PE, the leaf-only EVIs
and PEs (VXLAN), and warnings for cases where leaf traffic is not kept
apart, or where a PE gets no leaf BUM at all (an SRv6 argument length
mismatch). See [EVPN E-Tree](ch-02-47-bgp-evpn-e-tree.md#show).

JSON: `{ leafInterfaces, remoteLeafMacs, leafLabel, remoteLeafLabels,
leafArg, remoteLeafArgs, argLengthMismatch, leafOnlyEvis,
remoteLeafOnly, mixedPes, irb, roleConflicts, bumFiltered }`. Unlike the
other BGP views, its keys are camelCase. `bumFiltered` is false whenever
leaf BUM is not kept from other PEs' leaves: mixed PEs, or no leaf label or
leaf argument of this PE's own. A PE that gets no leaf BUM leaks none, so
`argLengthMismatch` does not make it false.

### `show evpn dup-addr`

Duplicate address detection (RFC 7432 §15): the configured limits,
then every address that is a duplicate or whose moves are being counted
in an open window.

```
r1> show evpn dup-addr
Duplicate address detection: max-moves 5 within 180s, freeze 300s

VNI       MAC               IP                                      State      Moves Location                 Detected
100       02:00:00:00:01:01 -                                       duplicate  5     local                    12s ago, recovers in 288s
100       02:00:00:00:01:01 10.10.0.101                             dup (MAC)  0     local                    -
100       02:00:00:00:02:02 -                                       counting   2     remote 10.0.0.12         -
```

`dup (MAC)` marks an IP that is a duplicate because its MAC is. With
detection off, the command prints `Duplicate address detection:
disabled`. See
[EVPN Duplicate Address Detection](ch-02-46-bgp-evpn-dup-addr.md#show-and-clear).

JSON: `{ enabled, max_moves, time, freeze, addresses: [ { vni, mac, ip,
duplicate, inherited, moves, location, detected_secs_ago,
recovers_in_secs } ] }`. `freeze` is `off`, `permanent`, or the freeze
time in seconds.

## Neighbor state

### `show bgp summary`

One section per AFI/SAFI configured on at least one neighbor, each
listing peer version, AS, message counters, uptime, FSM state, and
prefix counts received/sent.

```
r1> show bgp summary
IPv4 Unicast Summary:
BGP router identifier 192.0.2.1, local AS number 65000 VRF default vrf-id 0
RIB entries 42
Peers 1

Neighbor        V         AS   MsgRcvd   MsgSent   TblVer  InQ OutQ  Up/Down State       PfxRcd/Snt Hostname
192.0.2.2       4      65001        42        40        0    0    0 00:05:00 Established      42/10 r2
```

`PfxRcd/Snt` reads `N/A` until the session is Established and `NoNeg`
when the family was not negotiated with the peer. `Hostname` is the
peer's FQDN capability, or `N/A`. `TblVer`, `InQ` and `OutQ` are not
tracked and always read `0`.

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
