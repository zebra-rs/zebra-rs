# BGP allowas-in

RFC 4271 loop prevention makes a BGP speaker **reject any inbound route
whose AS_PATH already contains its own AS**. That is the right default,
but it gets in the way of one common design: two sites that reuse the
**same AS number** behind a shared provider. A route originated at one
site is re-advertised by the provider to the other, arrives carrying the
shared AS, trips the loop check, and is dropped.

`neighbor X allowas-in` resolves this on the **receiving** side. It
relaxes the inbound loop check for that one neighbor, so a route whose
AS_PATH contains the local AS is accepted instead of discarded.

This is the receive-side counterpart to
[AS Override](ch-02-12-bgp-as-override.md), which solves the same
shared-AS problem on the *advertising* side by rewriting the neighbor's
AS out of the path before it is sent. Use `allowas-in` when you control
the **receiver**; use `as-override` when you control the **advertiser**.

## The problem

Consider a line where `z1` and `z3` are both AS 65001, with a provider
`z2` (AS 65002) between them:

```
 ┌─────────┐  192.168.0.0/24  ┌─────────┐  192.168.1.0/24  ┌─────────┐
 │   z1    │ ──────────────── │   z2    │ ──────────────── │   z3    │
 │ AS65001 │                  │ AS65002 │                  │ AS65001 │
 │  .0.1   │                  │.0.2 .1.2│                  │  .1.3   │
 └─────────┘                  └─────────┘                  └─────────┘
 originates                                                  must learn
 10.0.0.1/32                                                 10.0.0.1/32
```

`z1` originates `10.0.0.1/32`; `z2` learns it with AS_PATH `65001`. When
`z2` re-advertises it to `z3` it prepends its own AS, sending
`65002 65001`. `z3` is AS 65001, sees `65001` in the path, and drops the
route as a loop — even though `z2` holds it fine. The two same-AS sites
cannot reach each other.

## What allowas-in does

AS_PATH is read right-to-left: the **right-most** AS is the origin, and
each transit speaker prepends on the **left**. In `65002 65001`, `65001`
is the origin (`z1`) and `65002` is the transit prepend (`z2`).

`allowas-in` has two mutually-exclusive modes that control *how many* —
or *where* — the local AS may appear:

- **count `<1-10>`** — accept the route while the local AS appears **at
  most `count` times** anywhere in the AS_PATH. The bare `allowas-in`
  form uses the default of **3** (FRR parity). With `count 3`,
  `65001 65001 65001 65002` (three occurrences) is accepted but
  `65001 65001 65001 65001` (four) is still dropped.
- **origin** — accept the route **only when every occurrence of the
  local AS is the originating (right-most) AS**, prepends at the origin
  included. A local AS in any *transit* position is still a loop. So
  `65002 65003 65001` and `65002 65001 65001` are accepted, but
  `65001 65002 65003` and `65001 65002 65001` are dropped.

In the topology above either mode lets `z3` accept `10.0.0.1/32`: there
is a single `65001`, and it is the origin.

## Configuration

`allowas-in` is a per-neighbor knob. Configure it on the receiver, on the
session toward the provider. The bare form takes the default budget of 3:

```yaml
router:
  bgp:
    global:
      as: 65001
      router-id: 192.168.1.3
    neighbor:
    - remote-address: 192.168.1.2
      remote-as: 65002
      enabled: true
      afi-safi:
      - name: ipv4
        enabled: true
      allowas-in:            # bare presence container → default count 3
```

`allowas-in:` with no value is the YAML spelling of a presence container;
the loader turns it into `set router bgp neighbor 192.168.1.2 allowas-in`.
To set an explicit budget, nest `count`; for origin-only mode, nest the
`origin` flag:

```yaml
      allowas-in:
        count: 5             # accept up to 5 occurrences
```

```yaml
      allowas-in:
        origin:              # accept the local AS only at the origin
```

The equivalent CLI forms share the same path:

```
set router bgp neighbor 192.168.1.2 allowas-in
set router bgp neighbor 192.168.1.2 allowas-in count 5
set router bgp neighbor 192.168.1.2 allowas-in origin
```

Because `count` and `origin` are a `choice`, setting one clears the
other.

### Re-advertisement after enabling

The loop check runs **on receipt**, before the route is stored — a
dropped route never enters the inbound Adj-RIB, so enabling `allowas-in`
on an already-established session does **not** retroactively recover it.
The neighbor has to re-send the route. Hard-reset the session so the
provider re-advertises it under the new setting:

```
clear bgp ipv4 neighbor 192.168.1.2
```

This is the key operational difference from an ordinary inbound policy
change, which re-evaluates the routes already held in the Adj-RIB-In.

Like the other per-neighbor knobs, `allowas-in` can also be set on a
[neighbor-group](ch-02-26-bgp-neighbor-group.md) and inherited by
every member; a statement on the neighbor itself wins.

## Verification

`show ip bgp neighbors` reports the active setting for the session:

```
  Allowas-in: 3 occurrence(s)
```

or, in origin mode:

```
  Allowas-in: origin
```

Then confirm the previously-rejected prefix is now installed. `z3` should
hold `10.0.0.1/32` with an AS_PATH of `65002 65001`:

```
show ip bgp 10.0.0.1/32
```

## Troubleshooting

The usual mistake is configuring `allowas-in` on the **wrong end**. It
belongs on the side that *accepts* the looped route — `z3` above — not on
the provider. If you control only the advertising side, the send-side
equivalent is [AS Override](ch-02-12-bgp-as-override.md), which rewrites
the AS out of the path instead of relaxing the receiver's check.

If the route still does not appear after enabling `allowas-in`, check
that:

- the session was **bounced** (`clear bgp ipv4 neighbor <addr>`) after
  the change, so the route was re-advertised and re-evaluated;
- the **mode is wide enough** — in `origin` mode a route with the local
  AS in a *transit* position is still dropped; switch to `count` if the
  local AS legitimately appears mid-path;
- the `count` budget covers the actual number of occurrences — a path
  with more copies of the local AS than `count` allows is still treated
  as a loop.
