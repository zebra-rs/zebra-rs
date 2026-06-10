# Neighbor Groups

Configuring many BGP peers that share the same attributes — the same
remote AS, the same enabled address families — gets repetitive and
error-prone fast. A **neighbor-group** is a named bundle of those
attributes, defined once under `router bgp` and referenced by any
number of peers. It is modelled on the IOS-XR `neighbor-group`, with a
deliberately focused attribute surface rather than a mirror of every
per-neighbor leaf.

Three kinds of peer can reference a group:

- a **static neighbor** (`neighbor X neighbor-group G`),
- an **interface-keyed unnumbered neighbor**
  ([IPv6 Unnumbered](ch-02-27-bgp-unnumbered.md)),
- a **dynamic peer** materialized from a listen-range
  ([Dynamic Neighbors](ch-02-01-dynamic-neighbors.md)) — there the
  group reference is mandatory, since an unknown caller has no
  per-neighbor config of its own.

## Attributes and precedence

A group currently carries two things:

- **`remote-as <asn>`** — the AS number a member peers with.
- **`afi-safi <family> enabled <true|false>`** — per-family toggles,
  using the same family names as the per-neighbor `afi-safi` list
  (`ipv4`, `ipv6`, `vpnv4`, `label-v4`, `evpn`, …).

The rule for both is: **anything set explicitly on the neighbor wins;
otherwise the neighbor inherits from the group.** For address families
there are three layers, lowest precedence first:

1. the built-in default — every peer starts with **IPv4 unicast
   enabled**;
2. the group's `afi-safi` opinions — `enabled true` switches a family
   on for members, `enabled false` switches it off (this is how a
   group turns the IPv4-unicast default *off*), and a family the group
   does not mention is left alone;
3. an explicit `neighbor X afi-safi <family> enabled <bool>` statement
   on the peer itself.

So a group with `afi-safi ipv4 enabled false` disables IPv4 unicast
for its members — except a member that itself carries
`afi-safi ipv4 enabled true`, which keeps it.

## How changes propagate

The two attributes apply on different schedules, matching what they
mean on the wire:

- **`remote-as` changes are immediate.** Setting or changing the
  group's `remote-as` propagates to every member that inherited it
  (members with their own `remote-as` are untouched). A member whose
  AS actually changed is bounced so the FSM renegotiates; deleting the
  group's `remote-as` (or the group) tears inherited members down.
- **`afi-safi` changes apply at the next capability negotiation.**
  Like the per-neighbor `afi-safi <family> enabled` knob, flipping a
  family in the group does *not* bounce established sessions — BGP
  capabilities are exchanged only in the OPEN message. Issue
  `clear bgp ipv4 neighbor <X>` when you want a live session to
  renegotiate with the new family set.

## Configuration

A route-reflector-style example: two clients share the group `RR`,
which supplies the remote AS and enables IPv4 and IPv6 unicast.

```yaml
router:
  bgp:
    global:
      as: 65001
      router-id: 192.168.0.1
    neighbor-group:
    - name: RR
      remote-as: 65002
      afi-safi:
      - name: ipv4
        enabled: true
      - name: ipv6
        enabled: true
    neighbor:
    - remote-address: 192.168.0.2
      enabled: true
      neighbor-group: RR
    - remote-address: 192.168.0.3
      enabled: true
      neighbor-group: RR
```

Neither neighbor needs its own `remote-as` or `afi-safi` list — both
come from the group. The equivalent CLI forms:

```
set router bgp neighbor-group RR
set router bgp neighbor-group RR remote-as 65002
set router bgp neighbor-group RR afi-safi ipv4 enabled true
set router bgp neighbor-group RR afi-safi ipv6 enabled true
set router bgp neighbor 192.168.0.2 neighbor-group RR
```

The reference is an ordinary string, not a strict cross-reference —
`neighbor X neighbor-group G` is accepted before `neighbor-group G`
exists, so configuration can be staged in any order. A peer whose
group reference is unresolved (group missing, or present but without a
`remote-as` when the peer has none of its own) simply stays dormant
until the group definition lands.

## Verification

`show ip bgp neighbor-group` lists every group with a member count;
the detail form shows the attribute set and which peers reference it:

```
show ip bgp neighbor-group
Name                      Remote-AS  Members
RR                            65002        2
```

```
show ip bgp neighbor-group RR
BGP neighbor-group: RR
  Remote-AS: 65002
  Afi-Safi:  ipv4 enabled, ipv6 enabled
  Members (2):
    192.168.0.2              remote-as 65002 (inherited) state Established
    192.168.0.3              remote-as 65002 (inherited) state Established
```

`(inherited)` marks members whose AS came from the group rather than a
per-neighbor `remote-as`. Both commands also have `--json` forms; the
JSON carries the same `afi_safi` map keyed by family name.

On the member side, `show ip bgp neighbors` reports the binding:

```
  Neighbor-group: RR (remote-as inherited)
```

## Troubleshooting

- **A member never leaves Idle.** The group reference is unresolved —
  the group does not exist yet, or carries no `remote-as` and the peer
  has none of its own. The daemon logs
  `neighbor-group reference unresolved … peer stays dormant`.
- **An afi-safi flip "did nothing".** Capability changes wait for the
  next OPEN exchange by design. `clear bgp ipv4 neighbor <X>` the
  member and re-check the `Neighbor Capabilities:` section of
  `show ip bgp neighbors`.
- **One member ignores the group's family setting.** That member has
  its own `afi-safi <family> enabled` statement, which outranks the
  group. Delete the per-neighbor leaf to fall back to inheritance.
