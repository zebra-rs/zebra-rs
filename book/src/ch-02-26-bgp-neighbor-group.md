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

A group carries the full set of per-neighbor knobs. The complete list,
grouped by function:

**Transport**
`remote-as`, `passive`, `update-source`, `port`, `ttl-security`,
`ebgp-multihop`, `tcp-mss`, `password`, `disable-connected-check`

**Per-family (afi-safi)**
`afi-safi <name> enabled`, `afi-safi <name> next-hop-self`

**Filtering and policy**
`policy in`, `policy out`, `prefix-set in`, `prefix-set out`

**AS-path handling**
`allowas-in [count <1–10>|origin]`, `as-override`,
`remove-private-as [all] [replace-as]`, `enforce-first-as`

**Route reflection**
`route-reflector client`

The precedence rule is the same for every one of them: **anything set
explicitly on the neighbor wins; otherwise the neighbor inherits from
the group.**

For address families there are three layers, lowest precedence first:

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

Several knobs are **presence-style** — they can only be stated "on",
matching the expressiveness of the per-neighbor command: `ttl-security`,
`as-override`, `remove-private-as`, `enforce-first-as`,
`disable-connected-check`, and `allowas-in`. Setting one in the group
enables it for every member that does not suppress it with an explicit
per-neighbor override.

## How changes propagate

Each knob propagates with the same ritual the equivalent per-neighbor
command uses:

- **`remote-as` changes are immediate.** Setting or changing the
  group's `remote-as` propagates to every member that inherited it
  (members with their own `remote-as` are untouched). A member whose
  AS actually changed is bounced so the FSM renegotiates; deleting the
  group's `remote-as` (or the group) tears inherited members down.
- **Session-bouncing knobs** — `port`, `ttl-security`, `ebgp-multihop`,
  `disable-connected-check` — propagate immediately and bounce every
  live member session so the change takes effect on the wire.
- **Reconnect-time knobs** — `tcp-mss` and `password` — re-key or
  clamp the listener and apply to new connections; existing sessions
  pick them up at the next reconnect.
- **Policy and prefix-set changes** re-resolve the filter chain and
  soft-replay routes for every affected member (the equivalent of
  `clear bgp ipv4 neighbor <X> soft in/out`).
- **No-bounce knobs** — `passive`, `allowas-in`, `as-override`,
  `remove-private-as`, `enforce-first-as`, `route-reflector client`,
  `next-hop-self` — apply without bouncing established sessions. The
  egress-signature ones (`route-reflector client`, `next-hop-self`,
  `as-override`, …) take effect on routes and sessions going forward.
- **`afi-safi` changes apply at the next capability negotiation.**
  Like the per-neighbor `afi-safi <family> enabled` knob, flipping a
  family in the group does *not* bounce established sessions — BGP
  capabilities are exchanged only in the OPEN message. Issue
  `clear bgp ipv4 neighbor <X>` when you want a live session to
  renegotiate with the new family set.
- **`update-source`** propagates to inherited members, but skips
  members whose address family does not match the configured source
  address (e.g. an IPv4 source is not applied to an IPv6-only session).
- **Dynamic (listen-range) members** are always passive regardless of
  the group's `passive` setting — an inbound caller materializes the
  peer and drives the connection.

## Configuration

A route-reflector-style example: two clients share the group `RR`,
which supplies the remote AS, enables IPv4 and IPv6 unicast with
next-hop-self on IPv4, enforces a TTL-security hop count, and marks
members as route-reflector clients.

```yaml
router:
  bgp:
    global:
      as: 65001
      router-id: 192.168.0.1
    neighbor-group:
    - name: RR
      remote-as: 65002
      ttl-security: null
      route-reflector:
        client: true
      afi-safi:
      - name: ipv4
        enabled: true
        next-hop-self: true
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

Neither neighbor needs its own `remote-as`, `afi-safi`, or policy
knobs — all come from the group. The equivalent CLI forms:

```
set router bgp neighbor-group RR
set router bgp neighbor-group RR remote-as 65002
set router bgp neighbor-group RR ttl-security
set router bgp neighbor-group RR route-reflector client true
set router bgp neighbor-group RR afi-safi ipv4 enabled true
set router bgp neighbor-group RR afi-safi ipv4 next-hop-self true
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
the detail form shows every configured knob and which peers reference
it:

```
show ip bgp neighbor-group
Name                      Remote-AS  Members
RR                            65002        2
```

```
show ip bgp neighbor-group RR
BGP neighbor-group: RR
  Remote-AS: 65002
  Afi-Safi:  ipv4 enabled nhs, ipv6 enabled
  TTL-security: enabled
  Route-reflector-client: true
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
