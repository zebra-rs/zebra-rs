# Dynamic Neighbors

A statically configured neighbor names its remote address up front.
That breaks down when the set of peers is open-ended — a route server,
a hub router, or a data-center fabric where new leaves appear without
a config change on the hub. **Dynamic neighbors** invert the model:
instead of enumerating peers, you authorize a **prefix range**, and any
BGP speaker that connects *from* an address inside the range is
accepted and materialized as a peer on the fly. This is the IOS-XR
`bgp listen range` / FRR `bgp listen range` model.

Because an unknown caller has no per-neighbor configuration of its
own, every listen-range must name a
[neighbor-group](ch-02-26-bgp-neighbor-group.md) — that group supplies
the peer's `remote-as` and its enabled address families.

```
 ┌─────────┐                ┌─────────┐
 │  hub    │ ◄───── SYN ─── │ spoke N │   spokes connect in from
 │ AS65001 │                │ AS65002 │   anywhere in 10.1.0.0/24;
 └─────────┘                └─────────┘   the hub configures no
   listen-range 10.1.0.0/24                per-spoke neighbor
```

Key properties:

- **Passive-only.** A dynamic peer is created when its TCP connection
  arrives; the local speaker never dials into a listen-range. The
  synthesized peer is marked passive for its lifetime.
- **Longest-prefix match.** Ranges may overlap; the most specific
  prefix that contains the source address wins, so a `/24` carve-out
  can reference a different group than the surrounding `/8`. IPv4 and
  IPv6 ranges are looked up per address family.
- **Bounded.** `listen-limit` (default **100**) caps how many dynamic
  peers may exist at once; past the cap, further matching connections
  are dropped at accept time. Setting it to `0` disables the ranges
  without removing them. A dynamic peer whose session ends is removed
  again (and frees its slot) rather than lingering in Idle.
- **Group-driven.** The peer inherits the group's entire attribute
  set — `remote-as`, the `afi-safi` families, and the whole-session
  knobs (`password`, `ttl-security`, policies, …) — with the usual
  precedence rules; see
  [Neighbor Groups](ch-02-26-bgp-neighbor-group.md). The group's
  `passive` opinion is moot here: dynamic peers are always passive.

## Configuration

The hub above, accepting any caller from `10.1.0.0/24` as an AS-65002
peer with IPv4 and IPv6 unicast enabled:

```yaml
router:
  bgp:
    global:
      as: 65001
      router-id: 10.0.0.1
    neighbor-group:
    - name: SPOKES
      remote-as: 65002
      afi-safi:
      - name: ipv4
        enabled: true
      - name: ipv6
        enabled: true
    dynamic-neighbors:
      listen-limit: 200
      listen-range:
      - prefix: 10.1.0.0/24
        neighbor-group: SPOKES
```

The equivalent CLI forms:

```
set router bgp dynamic-neighbors listen-limit 200
set router bgp dynamic-neighbors listen-range 10.1.0.0/24 neighbor-group SPOKES
```

`neighbor-group` is mandatory on each range. As elsewhere, the
reference is a plain string: the range can be configured before the
group exists, and connections simply keep being refused until the
group (and its `remote-as`) lands.

## Verification

A spoke that has connected shows up like any other peer —
`show bgp summary`, `show bgp neighbors` — identified by its source
address, and `show bgp neighbors <addr>` reports the binding:

```
  Neighbor-group: SPOKES (remote-as inherited)
```

The group detail view counts the spokes that are currently
materialized:

```
show bgp neighbor-group SPOKES
BGP neighbor-group: SPOKES
  Remote-AS: 65002
  Afi-Safi:  ipv4 enabled, ipv6 enabled
  Members (3):
    10.1.0.11                remote-as 65002 (inherited) state Established
    10.1.0.12                remote-as 65002 (inherited) state Established
    10.1.0.13                remote-as 65002 (inherited) state Established
```

## Troubleshooting

- **A caller inside the range is refused.** Check `listen-limit` — at
  the cap, additional connections are silently dropped — and confirm
  the referenced group exists *and* carries a `remote-as`; a range
  pointing at an unresolved group accepts nothing.
- **A caller matches the wrong group.** Overlapping ranges resolve by
  longest prefix; verify which range actually contains the source
  address.
- **The spoke connects but the wrong families negotiate.** Family
  enablement comes from the group's `afi-safi` list (IPv4 unicast on
  by default); a change there applies to a live spoke only after the
  session renegotiates — `clear bgp ipv4 neighbor <addr>`.
