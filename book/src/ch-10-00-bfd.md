# Bidirectional Forwarding Detection (BFD)

Bidirectional Forwarding Detection (BFD, RFC 5880) is a lightweight
hello protocol that detects a forwarding-path failure to an adjacent
system in **sub-second** time — far faster than the multi-second
hold/dead timers of the routing protocols themselves. zebra-rs runs a
single BFD subsystem that the routing protocols attach to: when a BFD
session drops, the subsystem notifies every protocol watching that
neighbour, and each one tears its adjacency or peering down
immediately (RFC 5882 §5) instead of waiting for its own timer.

This chapter covers the BFD subsystem as a whole — how it starts, the
session model, the transport, and the operational `show` commands. How
each protocol attaches BFD to a neighbour is documented in that
protocol's own BFD section:

- [BGP](ch-02-08-bgp-bfd.md) — per-neighbor, single- or multi-hop
- [IS-IS](ch-07-03-isis-bfd.md) — per-interface, single-hop
- [OSPFv2 / OSPFv3](ch-08-02-ospf-bfd.md) — per-interface, single-hop

The implementation follows the FRR command surface and semantics where
they align, so configurations written against FRR carry across with
little surprise; differences from FRR and Cisco IOS-XR are called out
where they matter.

## You do not enable BFD globally

There is **no global "turn BFD on" switch**. The BFD subsystem is
spawned automatically the moment any consumer is configured — a
`router bgp`, `router isis`, `router ospf`, or `router ospfv3` block —
and it is always brought up *before* the protocol that uses it, so the
order in which you type the configuration never matters. Attaching BFD
to a neighbour is then a single per-neighbour / per-interface flag:

```
router ospf {
  area 0 {
    interface eth0 {
      bfd { enable true; }
    }
  }
}
```

That is the whole story for the common case. The optional top-level
`bfd { … }` block (below) exists only to define reusable **profiles**;
it is not required to use BFD.

> This matches FRR, where `neighbor X bfd` / `ip ospf bfd` "just work"
> without a separate global daemon switch. Earlier revisions of
> zebra-rs required a top-level `bfd { }` block to exist first; that
> requirement has been removed.

## Session model

A BFD session is keyed by the tuple **(local address, remote address,
ifindex, hop-mode)**. Two systems each pick a random, non-zero local
*discriminator*; once packets are flowing each end echoes the other's
discriminator and the session is demultiplexed by discriminator on the
fast path. The session runs a small state machine — `Down → Init → Up`
— and reports each transition back to the attached protocols.

Multiple protocols can attach to the **same** neighbour: they share one
underlying session, and all of them are notified when it changes state.
The session is torn down only when the last consumer detaches.

Timers are negotiated from each side's *desired transmit* and *required
receive* intervals; the detection time is `received-tx-interval ×
detect-multiplier`. The shipped defaults are conservative:

| Parameter | Default |
|---|---|
| Transmit interval | 1000 ms |
| Receive interval | 1000 ms |
| Detect multiplier | 3 |

giving a ~3-second detection time out of the box. (See
[Profiles](#profiles-not-yet-applied) for the current status of tuning
these.)

## Single-hop vs multi-hop

| | Single-hop (RFC 5881) | Multi-hop (RFC 5883) |
|---|---|---|
| UDP port | 3784 | 4784 |
| TTL / Hop Limit on egress | 255 | 255 |
| Accepted received TTL | **exactly 255** (GTSM) | **≥ `minimum-ttl`** (default 254) |
| Use | directly-connected neighbour | neighbour reached over ≥ 1 router |

Single-hop sessions enforce the **GTSM** check (RFC 5082): a control
packet that did not arrive with TTL/Hop-Limit 255 has crossed a router
and is dropped. Multi-hop sessions relax this to a configurable floor
so a packet that legitimately crossed a few hops is still accepted but
a spoofed far-away packet is not.

OSPF and IS-IS sessions are **always single-hop** (their neighbours are,
by definition, on a shared link). BGP chooses per neighbour: directly
connected eBGP is single-hop, while iBGP and eBGP-over-loopback are
multi-hop — see the [BGP BFD](ch-02-08-bgp-bfd.md) section.

## IPv4 and IPv6

Both address families are supported. The subsystem listens on the v4
and v6 transports independently (on both 3784 and 4784); IPv6
link-local sessions — used by OSPFv3 and by IPv6 IS-IS / BGP — are
demultiplexed per **ifindex**, since the same `fe80::` address can
appear on several interfaces. The egress interface is pinned for
link-local destinations so packets leave the right link.

## Profiles (not yet applied)

A top-level `bfd { … }` block defines named parameter **profiles** that
a neighbour can reference by name:

```
bfd {
  profile FAST {
    detect-multiplier 3;
    transmit-interval 300;   // milliseconds
    receive-interval 300;
    minimum-ttl 250;         // multi-hop only
  }
}
```

> **Current limitation.** A `profile` reference on a neighbour is
> parsed and stored, but it is **not yet resolved into the live
> session** — every session currently runs with the conservative
> defaults in the table above (1000 ms / ×3). This means `show bfd
> peer` reports 1000 ms timers regardless of the profile you select.
> Wiring profiles through to session parameters is a shared follow-up
> across all three protocols. Until then, the top-level block and the
> per-neighbour `profile` leaf are accepted but have no effect on
> timers.

## Verifying sessions

Three `show` commands surface BFD state:

```
show bfd                  # one-line-per-session summary table
show bfd peer             # FRR-style detail block for every session
show bfd peer 10.0.0.2    # detail for a single peer
show bfd counters         # per-session control-packet counters
```

`show bfd` gives a quick health table:

```
Peer             State    Local/Remote Disc      Uptime     Iface
10.0.0.2         Up       0xd6b24a5/0x3f0a112    00:14:22   single-hop
```

`show bfd peer [<addr>]` prints the FRR-style indented detail block —
discriminators, status and up/down time, diagnostics, the negotiated
local and remote timers, and (for multi-hop) the minimum TTL. A fresh
session that has not yet heard from the peer shows `State Down` with a
remote discriminator of `0x0`; that means the local side is
transmitting but nothing is coming back — check that the peer also has
BFD configured toward this router and that UDP 3784/4784 is not
filtered on the path.

`show bfd counters` shows received / transmitted control-packet counts
per session (the RX counter is the reliable one for confirming the
receive path is alive).

Each command also accepts a trailing `json` for machine-readable output.

## What happens on failure

When a session transitions to `Down`, every attached protocol is
notified and reacts as if its own liveness timer had expired
(RFC 5882 §5): BGP sends the peer FSM a `Stop`, and OSPF / IS-IS tear
the adjacency down via the same path as a dead-timer / hold-timer
expiry, which re-runs SPF. Because BFD detects the failure in
well under a second, convergence starts far sooner than the protocol's
native timers would allow.

## Status and roadmap

- **Done:** single- and multi-hop, IPv4 and IPv6; BGP, IS-IS, OSPFv2
  and OSPFv3 attachment; the three `show` commands.
- **Not yet:** profile parameters are stored but not applied to live
  sessions (sessions use the defaults); BFD for **static routes** is a
  planned future phase; per-VRF OSPF BFD is not yet wired.
