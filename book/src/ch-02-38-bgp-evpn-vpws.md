# EVPN VPWS (E-Line over SRv6)

zebra-rs implements **EVPN VPWS** (Virtual Private Wire Service, RFC
8214) over an SRv6 data plane: a point-to-point **E-Line** that
cross-connects one local attachment circuit (AC) to one remote PE's AC
as a transparent wire — no MAC learning, no FDB, no flooding. The two
CEs behave as if joined by a cable: they share subnets and resolve each
other by ARP straight through the service.

Each side advertises a **per-EVI Ethernet A-D route (Type-1)** whose
Ethernet Tag is its *local* VPWS service instance id, carrying an
**SRv6 End.DX2 L2-Service Prefix-SID** (RFC 9252 §6.3) carved from the
BGP SRv6 locator. Importing the remote's Type-1 — matched by Ethernet
Tag == `remote-service-id` within the shared EVI — binds the remote SID
as the AC's cross-connect target. Forwarding runs in the
[eBPF data plane](ch-16-00-ebpf.md): the AC's ingress encapsulates every
frame (any EtherType)
MAC-in-SRv6 toward the remote SID, and the local End.DX2 decap emits
received frames raw on the same AC.

The RD is auto-derived as `router-id:evi`, the route-target as
`AS:evi`; the ESI is all-zero (single-homed) in this phase.

## Configuration

A VPWS service lives under the EVPN address family:

```
set router bgp global as 65001
set router bgp global router-id 10.0.0.1
set router bgp segment-routing srv6 locator LOC1
set router bgp afi-safi evpn vpws eline1 evi 100
set router bgp afi-safi evpn vpws eline1 local-service-id 101
set router bgp afi-safi evpn vpws eline1 remote-service-id 102
set router bgp afi-safi evpn vpws eline1 interface ce1
```

* `evi` scopes the auto-derived RD and RT; both ends must share it.
* `local-service-id` is advertised as our Type-1's Ethernet Tag; the
  remote end configures the same value as its `remote-service-id`
  (and vice versa — the ids cross).
* `interface` names the attachment circuit (the CE-facing port).
* The service's End.DX2 SID is carved dynamically from the BGP SRv6
  locator; no manual SID configuration.

The neighbor must negotiate the L2VPN/EVPN family
(`afi-safi evpn enabled true`).

### MTU signalling (RFC 8214 §3.1)

```
set router bgp afi-safi evpn vpws eline1 mtu 1500
```

Every VPWS Type-1 carries the **Layer-2 Attributes extended community**
(P bit set — single-homed primary) with the configured L2 MTU (0 /
unset = no check). When both ends signal non-zero MTUs that differ, the
remote is **not** bound — the service shows `mtu-mismatch` with the
offending remote MTU until the ends agree.

### VLAN-scoped services (End.DX2V)

```
set router bgp afi-safi evpn vpws eline2 evi 200
set router bgp afi-safi evpn vpws eline2 local-service-id 201
set router bgp afi-safi evpn vpws eline2 remote-service-id 202
set router bgp afi-safi evpn vpws eline2 interface ce1
set router bgp afi-safi evpn vpws eline2 vlan 30
```

`vlan` scopes the AC to one 802.1Q VID (RFC 8214 VLAN-based E-Line):
only tagged frames with that VID enter the cross-connect — the tag
crosses the service transparently — and the local SID becomes
**End.DX2V** (RFC 8986 §4.10), demuxing return traffic by inner VID
over the EVI's VLAN table. Tagged and untagged services can share the
same AC port: VID-scoped entries match first, everything else rides
the whole-port service.

> **Operational note:** VLAN offloads must be **off** on the CE side of
> the AC (`ethtool -K <if> txvlan off rxvlan off`). An offloaded tag
> travels as skb metadata, never in the packet bytes — and XDP, which
> classifies on bytes, cannot demux the VID. This is the standard
> requirement for any XDP VLAN path.

### Multihoming (RFC 8214 §5)

When the AC sits on a CE that is dual-homed to two PEs, both PEs configure
the same `ethernet-segment` (RFC 7432 — the shared ESI both advertise a
Type-4 under) and advertise the **same** VPWS service instance id: the pair
is one logical endpoint of the E-Line.

The service picks up the segment **from its attachment circuit** — the
segment declares an `interface`, the service declares the same one, and that
is the binding. Nothing else is needed:

```
router bgp
 afi-safi evpn
  ethernet-segment ES1
   esi 00:11:22:33:44:55:66:77:88:99
   redundancy-mode single-active
   interface ce1              <-- the segment claims ce1 ...
  vpws eline1
   evi 100
   local-service-id 101
   remote-service-id 103
   interface ce1              <-- ... and this AC is ce1, so ES1 binds
```

`show bgp evpn vpws` marks an inferred binding `(from ce1)`. This matches
how every commercial implementation works — IOS-XR, Junos, Arista and FRR
all configure the segment *on the interface*, so the AC is what identifies
it and the two cannot contradict each other.

The `ethernet-segment` leaf overrides that inference and is only needed in
two cases: several segments claim the same access port, or the segment
declares no `interface` of its own.

```
  vpws eline1
   interface ce1
   ethernet-segment ES2       <-- override; ES2 is used even if ES1 claims ce1
```

Two situations are reported rather than silently resolved:

* **Ambiguous** — more than one segment claims the AC. The service stays
  single-homed and `show` lists the candidates, because guessing would put
  it on the wrong ESI. Naming one on the leaf resolves it.
* **Interface mismatch** — the leaf names a segment whose `interface` is a
  different port. The override still wins (explicit config is respected),
  but `show` prints a `WARNING` line rather than swallowing the discrepancy.

The segment supplies two things. Its **ESI** replaces the all-zero one in
the service's Type-1, so the remote PE can tell that the routes it receives
from the two PEs are the same endpoint rather than two E-Lines. Its
**redundancy mode** drives the P/B bits of the Layer-2 Attributes extended
community:

| Mode | P/B advertised |
|---|---|
| (no `ethernet-segment`) | every service is primary — `P=1 B=0` |
| `all-active` | *every* attached PE is primary — `P=1 B=0` |
| `single-active` | the elected DF is `P=1 B=0`, its successor in the carving order is `P=0 B=1`, any further PE is `P=0 B=0` |

By default the election runs per `<ESI, VPWS service instance>`: the PEs
advertising the segment's Type-4 are ordered by ascending VTEP address and
the DF is ordinal `service-id mod N` (RFC 7432 §8.5 service carving). Keying
on the service instance rather than a fixed ordinal is what spreads
different E-Lines on one segment across both PEs instead of piling them all
onto the lowest address.

**Preference-based election** (Alg 2, draft-ietf-bess-evpn-pref-df) replaces
that hash with an explicit choice — set a preference on the segment and the
highest bid wins, ties broken by the lowest originating address:

```
  ethernet-segment ES1
   esi 00:11:22:33:44:55:66:77:88:99
   redundancy-mode single-active
   interface ce1
   df-election
    preference 300
    ac-df           # optional: advertise the AC-Influenced DF capability
```

Preference is per-*segment*, so one PE wins every service instance on it —
that is the trade against carving, and the reason to use it: the operator
pins the DF instead of accepting a hash. The value rides each PE's Type-4 in
the DF Election extended community, so `show bgp evpn` on a peer renders
`df-election:alg2:pref300`.

Every PE on the segment must advertise the same algorithm. RFC 8584
negotiation drops the whole segment back to service carving if any one of
them disagrees, so a half-configured segment silently reverts rather than
splitting the election — `show bgp evpn ethernet-segment` reports the
negotiated algorithm and each PE's bid.

This interoperates with IOS-XR `service-carving preference-based`, Junos
`df-election-type preference`, Arista
`designated-forwarder election algorithm preference` and FRR
`evpn mh es-df-pref`.

Because the candidate set comes from the Type-4 routes in the Loc-RIB, the
role is re-elected whenever a PE joins or leaves the segment — a peer's
Type-4 arriving or being withdrawn re-runs the election and re-advertises
the Type-1 if this PE's own role changed, with no local config change. A PE
whose own Type-4 is not selected yet advertises primary rather than
blackholing the service while the segment converges.

**Startup delay** covers the one case where that last rule is wrong. A PE
that has just booted has not learned the other PEs' Type-4 routes yet, so an
election run immediately sees an empty candidate set, elects this PE the DF
for every service instance, and starts forwarding toward a CE the incumbent
DF is already serving — the CE sees duplicates. `startup-delay` holds the PE
out of the segment for that many seconds after it joins (on a reboot, from
when the startup configuration is applied):

```
  ethernet-segment ES1
   esi 00:11:22:33:44:55:66:77:88:99
   redundancy-mode single-active
   interface ce1
   df-election
    startup-delay 180
```

While the hold runs the PE **withholds this segment's ES routes** — the
Type-4 and the per-ES A-D — and forces every VPWS service on the segment to
`P=0 B=0`. Suppressing the advertisement is what makes the hold safe:
deferring only the local election would leave the other PEs still seeing our
Type-4, still running the same deterministic election, and free to hand the
DF role to a PE that is refusing to forward. Withholding the routes keeps us
out of their candidate sets entirely, so the incumbent simply keeps
forwarding until we join.

The corollary is that a segment with no other PE on it — single-homed, or
one whose peer is down — is out of service for the whole delay, since there
is no incumbent for the hold to protect. That is why this is off by default.
Clearing the leaf releases a hold in flight immediately rather than making
the operator wait out a timer they have just cancelled, and
`show bgp evpn ethernet-segment` reports the remaining time:

```
Ethernet Segment: ES1
  ESI: 00:11:22:33:44:55:66:77:88:99
  Redundancy mode: single-active
  Interface: ce1
  Startup hold: 143s of 180s remaining (ES routes suppressed)
  Member VTEPs (1):
    [0] 192.168.0.2
```

This interoperates with IOS-XR `timers peering`, Junos
`designated-forwarder-election-hold-time` and FRR `evpn mh startup-delay`.

**Remote selection** — which of a multihomed pair this PE binds — ranks the
advertised remotes per RFC 8214 §5: primary over backup, non-designated
(`P=0 B=0`) dropped, lowest originator breaking a tie so both ends agree.
Losing the primary re-selects rather than tearing the E-Line down. Two
details matter in practice:

* **MTU is filtered before the ranking**, so a primary whose MTU clashes
  steps aside for a compatible backup instead of wedging the service.
* **The per-ES Ethernet A-D route is the liveness gate**: a candidate on a
  non-zero ESI is usable only while its PE advertises one, which is how
  RFC 7432 §8.2 mass withdraw takes effect.

A single-homed remote (all-zero ESI) is always usable regardless of the
bits — an implementation that omits the Layer-2 Attributes EC decodes as
`P=0 B=0`, and excluding those would break every plain point-to-point peer.

> **Note:** all-active signals correctly but is not load-balanced — one end
> is selected and used, with the other standing by.

## Show command

```
> show bgp evpn vpws
VPWS service: eline1
  EVI: 100
  Service ID: local 101, remote 102
  Interface: ce1
  Local SID (End.DX2): fcbb:bbbb:1:40::
  Remote SID: fcbb:bbbb:2:40::
  State: up
```

A multihomed service adds its segment and elected role. `(from ce1)` marks a
binding inferred from the AC; an overridden one is printed without it:

```
  Ethernet Segment: ES1 (from ce1) (ESI 00:11:22:33:44:55:66:77:88:99, single-active)
  Role: backup (DF 192.168.0.2)
```

The problem cases each print distinctly, so none of them can be mistaken for
a deliberately single-homed service:

```
  Ethernet Segment: ES9 (no such segment)
  Ethernet Segment: ambiguous — ES1, ES2 claim ce1; name one explicitly
  Ethernet Segment: ES1 (ESI unset)
  Ethernet Segment: ES2 (ESI …, single-active)
  WARNING: segment interface ce7 differs from AC ce1
```

`json` is supported. The state progresses `partial-config` (mandatory
leaves missing) → `pending` (config complete, no router-id / locator
yet) → `advertised` (Type-1 originated, remote not matched) →
`up` (remote SID bound to the AC), with `mtu-mismatch` reported when a
matching remote is rejected by the MTU check.

## Reconciliation

The service re-syncs — withdraw + re-originate + re-derive the AC
binding from the EVPN Loc-RIB — on any leaf change, router-id rebind,
and locator (re)resolution. The Loc-RIB rescan means ordering does not
matter: a remote Type-1 that arrived *before* the service was
configured (or re-pointed) is found without waiting for a route churn.

## Scope

Multihoming covers both directions: the Type-1 carries the segment's ESI and
DF-elected P/B bits, and remote selection honours them (prefer `P`, fail over
to `B`, per-ES A-D mass withdraw). Not yet implemented — all-active load
balancing across both remote SIDs, and the
control word (`C` is always 0). Forwarding requires the
[eBPF data plane](ch-16-00-ebpf.md)
(`system ebpf enabled` to run the engine, `system cradle enabled` to tee the
service into it); the kernel has no End.DX2/DX2V seg6local action, so these
SIDs are never installed via netlink.
