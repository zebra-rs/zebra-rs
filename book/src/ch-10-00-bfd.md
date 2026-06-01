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

There is **no global "turn BFD on" switch**, and there are **no BFD
configuration leaves of its own**. The BFD subsystem is spawned
automatically the moment any consumer is configured — a `router bgp`,
`router isis`, `router ospf`, or `router ospfv3` block — and it is
always brought up *before* the protocol that uses it, so the order in
which you type the configuration never matters. Attaching BFD to a
neighbour is then a single per-neighbour / per-interface flag:

```
router ospf {
  area 0 {
    interface eth0 {
      bfd { enable true; }
    }
  }
}
```

That is the whole story. All BFD is configured *per protocol*; there is
no standalone `bfd { peer … }` or `bfd { profile … }` block — earlier
revisions had both, but they were inert (parsed but never wired to a
live session) and have been removed. The top-level `bfd` keyword exists
only as the FRR-style enable anchor and takes no sub-configuration.

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
detect-multiplier`. The shipped defaults are aligned with FRR:

| Parameter | Default |
|---|---|
| Transmit interval | 300 ms |
| Receive interval | 300 ms |
| Detect multiplier | 3 |

giving a **~900 ms** detection time out of the box. These intervals are
not currently tunable (the configuration leaves that would set them
were removed — see [Tuning](#tuning-intervals)); every session runs
with the defaults above.

### Slow transmit while not Up

Per RFC 5880 §6.8.3, while a session is **not** `Up` the transmit
interval is clamped to **at least one second**, regardless of the
configured rate. This keeps a session that is still coming up — or that
is probing a dead neighbour — from sending at the full sub-second rate.
The configured (fast) rate is restored the moment the session reaches
`Up`. Because this changes the advertised interval, zebra-rs announces
the change with a **Poll Sequence** (§6.8.7): the `Poll` bit is set on
outgoing packets across the up/down boundary until the peer answers with
a `Final`. zebra-rs both initiates Poll Sequences and answers a peer's
Poll with a Final.

### Local source address

A session's local address — the source address on the control packets it
sends — is taken from the consumer. For BGP this is the neighbour's
`update-source`; for OSPF / IS-IS it is the interface address the
protocol already uses. When no source is configured the address is left
unspecified and the kernel selects one per the route. The chosen source
is what `show bfd peers` reports as `Local address`.

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

The two transports are kept strictly separate: a packet that arrives on
the single-hop port (3784) is never allowed to drive a multi-hop session
and vice-versa, even when the same neighbour has both.

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

## Tuning intervals

There is currently **no way to tune the BFD timers** — every session
runs with the FRR-aligned defaults (300 ms / ×3 ⇒ ~900 ms detection).

Earlier revisions accepted a top-level `bfd { profile … }` block plus a
per-neighbour / per-interface `profile <name>` reference, but the
profile parameters were never resolved into the live session, so they
had no effect on timers. The top-level block has been removed. A
per-protocol `bfd { … profile <name>; }` leaf may still parse for
backward compatibility, but there is nowhere to define a profile and it
changes nothing. Configurable timers (per-protocol or via a reinstated
profile mechanism) are a possible future addition.

## Verifying sessions

Three `show` commands surface BFD state:

```
show bfd                   # one-line-per-session summary table
show bfd peers             # FRR-style detail block for every session
show bfd peers 10.0.0.2    # detail for a single peer
show bfd counters          # per-session control-packet counters
```

`show bfd` gives a quick health table:

```
Peer             State    Local/Remote Disc      Uptime     Iface
10.0.0.2         Up       0xd6b24a5/0x3f0a112    00:14:22   single-hop
```

`show bfd peers [<addr>]` prints the FRR-style indented detail block —
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

## Echo function

The BFD **Echo function** (RFC 5880 §6.4 / RFC 5881 §6) is a forwarding-plane
liveness test: a node sends a *self-addressed* UDP/3785 packet that the peer's
forwarding plane loops straight back, and times the round trip. Because the
loop never enters the peer's BFD control software, it detects a forwarding
fault even while control packets still flow — and it lets a node slow its
control-packet rate while keeping fast detection. Echo is **single-hop IPv4
only** (RFC 5883 multi-hop has no Echo).

The two halves are independent and zebra-rs implements both, offloaded to a
per-interface XDP/eBPF helper, **`xdp-bfd-echo`**:

- **Responder** — when we advertise a non-zero `Required Min Echo RX Interval`,
  the helper's XDP program loops a peer's Echo back in the data plane
  (decrementing TTL so it returns at 254, the way a forwarding hop would), so
  the *peer* gets fast detection. We only advertise non-zero once the helper is
  confirmed running, so the promise to loop is honest.
- **Originator** — the helper sends our Echo from a raw `AF_PACKET` socket and
  the XDP program arms a per-session in-kernel `bpf_timer` on each return; if
  returns stop for `interval × detect-mult`, the session goes `Down` with
  diagnostic `Echo Function Failed` (RFC 5880 §6.8.5). We only originate while
  the session is `Up` and the peer advertised a non-zero echo-rx (§6.8.9).

The helper is reference-counted **per interface**: one `xdp-bfd-echo` process is
spawned for each interface that has at least one Echo-enabled session, shared by
all sessions on that link, and stopped when the last one goes away. It needs
`cap_net_admin,cap_bpf` (load/attach XDP) and `cap_net_raw` (the originator's
raw socket); the packaged install grants these. A node with no Echo configured
runs no helper and advertises `Required Min Echo RX Interval = 0`.

Echo is enabled per attachment — today on OSPF interfaces, where `echo-mode`
selects the role (`transmit` / `receive` / `both`) and
`echo-transmit-interval` / `echo-receive-interval` set the rates; see
[OSPF BFD](ch-08-02-ospf-bfd.md#echo). `show bfd peers` reports the negotiated
`Echo receive interval` / `Echo transmission interval`.

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
  and OSPFv3 attachment; the three `show` commands; FRR-aligned 300 ms
  defaults; RFC 5880 §6.8.3 slow-transmit-while-not-Up with §6.8.7 Poll
  Sequences (both initiating and answering); BGP `update-source`
  inherited as the session's local address; the **Echo function**
  (RFC 5880 §6.4, single-hop IPv4) — both reflecting a peer's Echo and
  originating our own, offloaded to the `xdp-bfd-echo` XDP/eBPF helper
  (see [Echo function](#echo-function) below), with per-role
  (`transmit` / `receive` / `both`) config and an instance-level
  `router ospf { bfd {} }` default inherited and overridden per interface.
- **Not yet:** configurable control-packet timers (the intervals are
  fixed at the defaults); Echo on IS-IS and BGP (OSPF only today); BFD
  for **static routes**; per-VRF OSPF BFD.
