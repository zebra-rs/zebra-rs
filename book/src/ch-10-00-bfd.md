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
had no effect on timers. Both the top-level block and the per-protocol
`profile` leaf have been removed. Configurable timers (per-protocol or
via a reinstated profile mechanism) are a possible future addition.

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

## Tracing

The BFD task is quiet by default. A single runtime flag turns on its
diagnostic traces — session FSM transitions, control-packet handling, and
the `xdp-bfd-echo` helper lifecycle (Echo and the in-kernel expiration
watchdog it hosts):

```
set bfd tracing true     # enable
set bfd tracing false    # disable (or: delete bfd tracing)
```

It is a runtime toggle — no restart, and no rebuild — backed by a single
global flag, so it also covers the parts of BFD that run outside the main
task (the socket read/write tasks and the per-interface Echo reflector
IPC). It is not per-session or per-interface; it is on or off for the
whole BFD task.

The info- and warn-level traces appear at the **default** log level once
the flag is on, so `set bfd tracing true` is usually enough. The more
verbose per-packet, debug-level traces additionally need the log level
raised (e.g. `RUST_LOG=debug`), matching their original verbosity. With
the flag off, every BFD trace is suppressed regardless of `RUST_LOG`.

This is distinct from the per-protocol BFD tracing under
`router bgp tracing { bfd }`, `router isis tracing { bfd }`, etc., which
trace how *that protocol* reacts to BFD events; `set bfd tracing` traces
the BFD task itself.

## Echo function

The BFD **Echo function** (RFC 5880 §6.4 / RFC 5881 §6) is a forwarding-plane
liveness test: a node sends a UDP/3785 packet crafted so the peer loops it
straight back without its BFD software ever processing it, and times the round
trip. Because the loop never enters the peer's BFD control software, it
detects a forwarding fault even while control packets still flow — and it lets
a node slow its control-packet rate while keeping fast detection. Echo is
**single-hop only** (RFC 5883 multi-hop has no Echo); **both IPv4 and IPv6**
are supported.

The two halves are independent and zebra-rs implements both, offloaded to a
per-interface XDP/eBPF helper, **`xdp-bfd-echo`**:

- **Responder** — when we advertise a non-zero `Required Min Echo RX Interval`,
  the helper's XDP program loops a peer's Echo back in the data plane, so the
  *peer* gets fast detection. We only advertise non-zero once the helper is
  confirmed running, so the promise to loop is honest. The loop differs per
  family to match what real peers send: IPv4 Echo is *self-addressed* and
  looped as a forwarding hop (TTL decremented to 254), while IPv6 Echo (as FRR
  sends it) is *peer-addressed*, so the reflector also swaps the IPv6
  source/destination and decrements the Hop Limit — both interop-validated
  against FRR `echo-mode`.
- **Originator** — the helper sends our Echo from a raw `AF_PACKET` socket and
  the XDP program arms a per-session in-kernel `bpf_timer` on each return; if
  returns stop for `interval × detect-mult`, the session goes `Down` with
  diagnostic `Echo Function Failed` (RFC 5880 §6.8.5). We only originate while
  the session is `Up` and the peer advertised a non-zero echo-rx (§6.8.9).

The helper is reference-counted **per interface**: one `xdp-bfd-echo` process is
spawned for each interface that has at least one Echo-enabled (or
[`detect-offload`](#offloading-expiration-detection-detect-offload)-enabled)
session, shared by all sessions on that link, and stopped when the last one
goes away. It needs
`cap_net_admin,cap_bpf` (load/attach XDP) and `cap_net_raw` (the originator's
raw socket); the packaged install grants these. A node with no Echo configured
runs no helper and advertises `Required Min Echo RX Interval = 0`. Deployment,
attach modes, and troubleshooting are covered in
[The XDP/eBPF Data-Plane Helper](ch-10-01-bfd-xdp-helper.md).

Echo is enabled per attachment — on OSPFv2/v3 and IS-IS interfaces, and on
single-hop eBGP neighbours, where `echo-mode` selects the role
(`transmit` / `receive` / `both`) and `echo-transmit-interval` /
`echo-receive-interval` set the rates; see
[OSPF BFD](ch-08-02-ospf-bfd.md#echo), [IS-IS BFD](ch-07-03-isis-bfd.md#echo),
and [BGP BFD](ch-02-08-bgp-bfd.md#echo). An IPv6-only session (an OSPFv3 or
IS-IS adjacency over link-locals, a v6 eBGP neighbour) runs IPv6 Echo the same
way. Echo configuration changes apply to **live** sessions on commit — no
session bounce. `show bfd peers` reports the negotiated
`Echo receive interval` / `Echo transmission interval`.

## Offloading expiration detection (`detect-offload`)

Detection of a *silent* failure — the peer's control packets simply stop
arriving — normally rides on a userspace timer (RFC 5880 §6.8.4): every
valid packet resets it, and its expiry drives the session `Down` with
`Control Detection Time Expired`. That timer races the daemon's event
loop, which has two failure modes under load:

- **false Down** — packets are *arriving* but sit unprocessed in the
  socket queue while the daemon is busy (a BGP churn, a large SPF, a
  config commit), so the timer fires anyway;
- **late Down** — the peer really is gone, but the expiry event waits
  behind the same backlog.

`detect-offload` moves that timing into the kernel, using the same
per-interface `xdp-bfd-echo` helper as the [Echo
function](#echo-function). Once the session is `Up`, the helper's XDP
program *observes* every BFD control packet (UDP 3784 at TTL 255) on the
interface: it matches the packet's `Your Discriminator` against the
session, re-arms a per-session in-kernel `bpf_timer`, and **passes the
packet up unchanged** — the daemon still runs the full state machine,
Poll/Final handling, and timer negotiation on every packet; only the
liveness clock lives in the kernel. If control packets stop for the
negotiated detection time, the timer fires in softirq and the session
goes `Down` exactly as a userspace expiry would.

Because the re-arm happens at packet *arrival* (before any socket
queueing) and the expiry fires in softirq (no event-loop latency),
detection neither false-fires nor waits on a busy daemon — which is
what makes aggressive detection times honest.

Notes and guard-rails:

- **Up sessions only.** Before the session is established the peer may
  send `Your Discriminator = 0`, which cannot be matched in the kernel;
  zebra-rs arms the watchdog on the `Up` transition and disarms it when
  the session leaves `Up`. Renegotiated timers retune the armed value
  automatically.
- **Single-hop only.** The helper attaches per interface; multi-hop
  ingress is not bound to one (and its TTL floor is below the GTSM 255
  the observer requires). IPv4 and IPv6 are both supported.
- **The userspace timer stays as a backstop.** While the watchdog is
  armed, the normal detection timer keeps running, stretched to 4× the
  detection time; if the helper process ever dies, zebra-rs reverts the
  session to ordinary userspace detection immediately.
- **Honesty gate.** The watchdog is only armed once the helper is
  confirmed running — if it cannot start (missing binary, capabilities,
  kernel without XDP/`bpf_timer`), detection simply stays in userspace.
  A watchdog-only helper needs `cap_net_admin,cap_bpf` (no `cap_net_raw`
  — there is no transmit half; the daemon keeps sending its own control
  packets). See
  [The XDP/eBPF Data-Plane Helper](ch-10-01-bfd-xdp-helper.md) for
  requirements and troubleshooting.

It is enabled per attachment, with the same per-interface /
per-neighbour + instance-level inheritance as `echo-mode` — see
[OSPF BFD](ch-08-02-ospf-bfd.md#offloading-expiration-detection),
[IS-IS BFD](ch-07-03-isis-bfd.md#offloading-expiration-detection), and
[BGP BFD](ch-02-08-bgp-bfd.md#offloading-expiration-detection)
(single-hop neighbours; BGP sessions are keyed by the connected
interface so the helper knows where to attach). `show bfd peers`
reports where detection currently runs:

```
    Detection timeout: 900ms
    Detection runs in: kernel/XDP (900ms)
```

(`userspace` when the watchdog is not armed.)

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
  (RFC 5880 §6.4, single-hop, IPv4 **and** IPv6) — both reflecting a
  peer's Echo and originating our own, offloaded to the `xdp-bfd-echo`
  XDP/eBPF helper (see [Echo function](#echo-function) below), with
  per-role (`transmit` / `receive` / `both`) config applied live on
  commit and an instance-level `router <proto> { bfd {} }` default
  inherited and overridden per interface / neighbour. Echo is
  configurable on OSPFv2/v3, IS-IS, and single-hop eBGP (BGP echo is
  inert on multihop sessions — RFC 5883 has no Echo); the IS-IS
  attachment additionally pins a BFD-Down neighbour below `Up`
  (RFC 5882 §3.2 hold-down — see
  [IS-IS BFD](ch-07-03-isis-bfd.md#hold-down-while-bfd-is-down)).
  **In-kernel expiration detection** (`detect-offload`,
  RFC 5880 §6.8.4 evaluated in an XDP `bpf_timer` — see
  [Offloading expiration detection](#offloading-expiration-detection-detect-offload)),
  configurable on OSPFv2/v3 and IS-IS interfaces and on single-hop BGP
  neighbours.
- **Not yet:** configurable control-packet timers (the intervals are
  fixed at the defaults); BFD for **static routes**; per-VRF OSPF BFD;
  a BFD `profile` mechanism.
