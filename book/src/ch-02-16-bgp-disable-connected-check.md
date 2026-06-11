# BGP disable-connected-check

By default an **eBGP** session is expected to be a single IP hop: the
egress TTL is 1 (see
[TTL: eBGP Multihop and Security](ch-02-11-bgp-ttl-security.md)) and the
neighbor is expected to live on one of the router's directly-connected
subnets. zebra-rs enforces the second half of that expectation with the
**connected-network check**: before dialing a single-hop eBGP neighbor it
verifies the neighbor's address is on a connected subnet, and holds the
session down otherwise. `disable-connected-check` removes that
requirement for one neighbor.

## When you need it

The canonical case is two routers that are **directly connected at layer
2** but peer eBGP using addresses that are **not on the shared subnet** —
almost always loopbacks:

```
        10.0.0.0/24 (shared link)
 ┌─────────┐                 ┌─────────┐
 │   R1    │─────────────────│   R2    │
 │ lo .255 │                 │ lo .255 │
 │  .0.1/32│                 │  .0.2/32│
 └─────────┘                 └─────────┘
   AS 65001                    AS 65002
   peer 10.255.0.2  ←──────→  peer 10.255.0.1
```

R1 and R2 reach each other's loopback through a static (or IGP) route over
the link. Because they are L2-adjacent, a TTL-1 BGP packet still arrives at
the neighbor — no router decrements it — so **`ebgp-multihop` is not
required and would be wrong** (it would weaken the single-hop guarantee for
no reason). The only obstacle is the connected check, since `10.255.0.2`
is not on R1's connected `10.0.0.0/24`. `disable-connected-check` lifts
exactly that obstacle while leaving the TTL at 1.

## What the check does

The check governs **only a single-hop eBGP session** — eBGP whose egress
TTL is 1, i.e. neither `ebgp-multihop` nor `ttl-security` is set. For such
a peer:

- If the neighbor's address falls inside one of the router's
  directly-connected subnets (learned from interface addresses), the
  session is dialed normally.
- Otherwise the session is **held in `Active`**: zebra-rs does not open the
  TCP connection. It re-evaluates whenever a connected route to the peer
  appears, so a session that was waiting on an interface coming up dials as
  soon as it can.

The check **does not apply** to iBGP, to `ebgp-multihop` sessions, to
`ttl-security` (GTSM) sessions, or to unnumbered / link-local peers — those
are either intentionally multi-hop or directly attached by construction. On
those neighbors `disable-connected-check` is a no-op.

If zebra-rs has no interface-address information yet (for example very
early in startup), the check **fails open** so a transient lack of
knowledge never wedges a session — matching FRR's behaviour when it has no
connectivity information from the RIB.

> This mirrors FRR / Cisco IOS `neighbor X disable-connected-check`
> (FRR also accepts the legacy spelling `enforce-multihop`). FRR gates the
> same case through next-hop tracking; zebra-rs gates it at
> connect-initiation, which is observably equivalent: the session stays
> down until the neighbor is connected or the check is disabled.

## Configuration

`disable-connected-check` is a per-neighbor flag. Set it on the end(s)
that dial the non-connected address; in the loopback case that is both
ends.

```yaml
router:
  bgp:
    global:
      as: 65001
      router-id: 10.255.0.1
    neighbor:
    - remote-address: 10.255.0.2
      remote-as: 65002
      enabled: true
      afi-safi:
      - name: ipv4
        enabled: true
      update-source: 10.255.0.1
      disable-connected-check: {}
```

`disable-connected-check: {}` is the YAML spelling of a presence
container — the key is present with no children, which the loader turns
into `set router bgp neighbor 10.255.0.2 disable-connected-check` (the
legacy `disable-connected-check: null` spelling still loads the same
way). The FRR / IOS-style CLI form is the same path:

```
set router bgp neighbor 10.255.0.2 disable-connected-check
```

`update-source` is normally configured alongside it so the session sources
from the loopback the neighbor expects.

Toggling `disable-connected-check` on a session that is already up bounces
it (the same teardown `clear bgp <peer>` performs): enabling it lets a held
neighbor connect, and disabling it resets a session that only came up
because of the override.

Like the other per-neighbor knobs, `disable-connected-check` can also be
set on a [neighbor-group](ch-02-26-bgp-neighbor-group.md) and inherited
by every member; a statement on the neighbor itself wins.

## Verification

`show ip bgp neighbor <addr>` reports the active policy:

```
  Connected-network check disabled (eBGP peer may be unconnected at TTL 1)
```

A neighbor still held by the check shows a non-`Established` state (it sits
in `Active`, never opening a connection). The classic symptom of a
**missing** `disable-connected-check` is therefore an eBGP session to a
loopback that never leaves `Active` even though the loopback pings: add
`disable-connected-check` (do **not** reach for `ebgp-multihop` on a
directly-connected peer).
