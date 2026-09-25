# STAMP

Modern traffic engineering increasingly steers on *latency* rather than
hop count or static cost. zebra-rs treats per-link delay, jitter, and
loss as first-class link attributes: they are advertised in the IGP and
can be selected as the metric a Flexible Algorithm optimizes, so a
delay-sensitive algorithm computes shortest-*latency* paths instead of
shortest-cost ones.

The feature is split into two cleanly separated planes — the same
separation Cisco IOS-XR (SR Performance Measurement) and Nokia SR-OS
(OAM-PM / Link Measurement) use, and the architecture zebra-rs
interoperates with:

- **Measurement plane** — a node-to-node protocol that actively probes
  a link and derives its delay/jitter/loss. This is TWAMP Light
  (RFC 5357 Appendix I) and its successor STAMP (RFC 8762, with the
  optional TLVs of RFC 8972 and the SR extensions of RFC 9503). It
  produces numbers; it distributes nothing.
- **Distribution plane** — the IGP carries those numbers to every router
  as link attributes (IS-IS RFC 8570, OSPFv2 RFC 7471), and the
  Flexible Algorithm SPF consumes them (RFC 9350 metric-type 1).

The two planes meet at one struct: the per-interface `te-metric`. The
measurement plane writes it; the IGP reads it. That seam is what lets
the distribution side be built, tested, and operated independently of
the live prober.

## Current status

**All three planes are implemented** — measurement, distribution, and
consumption — end to end:

| | Measurement (STAMP) | Origination | Flex-Algo consumption (metric-type 1) |
|---|---|---|---|
| IS-IS | yes — IPv4 and IPv6 link-local | RFC 8570 sub-TLVs, inline + ASLA | yes |
| OSPFv2 | yes — IPv4 | RFC 7471 attributes in ASLA | yes |
| OSPFv3 | yes — IPv6 link-local | RFC 7471 attributes in ASLA | yes |

The per-interface `te-metric` fields can be **driven two ways**, and the
two are interchangeable because they write the same struct:

- **Statically**, from per-interface configuration (the `te-metric`
  block below) — useful for lab topologies and for pinning a value.
- **Dynamically**, from the live STAMP prober (the `te-metric
  measurement` block) — the active measurement plane probes each link
  and feeds the damped result into the same fields.

A statically configured value and a measured one are indistinguishable
downstream: origination, the ASLA, and Flex-Algorithm SPF neither know
nor care which writer produced the number. When both are present on a
link the configured value wins **per field** — a hand-set bound is
authoritative and the measured stream backfills only the fields left
unset.

> **Address families** — OSPFv2 is IPv4-only on the wire, so it cannot
> measure a link that carries no IPv4. IS-IS and OSPFv3 both measure over
> the link's IPv6 link-local pair, so an IPv6-only fabric is fully
> covered by either. See [The measurement plane](#the-measurement-plane).

## Configuration

Each link carries an optional `te-metric` container. All delay values
are in **microseconds**; `loss` is the raw RFC 8570/7471 encoding in
units of 0.000003 % (so the maximum, 16777214, is ≈ 50.33 %).

### IS-IS

```
router isis {
  interface eth1 {
    te-metric {
      unidirectional-delay 1000;
      min-delay 900;
      max-delay 1200;
      delay-variation 50;
      loss 0;
    }
  }
}
```

### OSPFv2

OSPF declares interfaces inside the area they belong to, so `te-metric`
lives one level deeper:

```
router ospf {
  area 0 {
    interface eth1 {
      te-metric {
        unidirectional-delay 1000;
        min-delay 900;
        max-delay 1200;
        delay-variation 50;
        loss 0;
      }
    }
  }
}
```

| Leaf | Range | Units | Wire attribute |
|---|---|---|---|
| `unidirectional-delay` | 0..16777215 | µs | Average one-way delay |
| `min-delay` | 0..16777215 | µs | Min of the Min/Max delay attribute |
| `max-delay` | 0..16777215 | µs | Max of the Min/Max delay attribute |
| `delay-variation` | 0..16777215 | µs | Jitter |
| `loss` | 0..16777214 | 0.000003 % | Link loss |

`min-delay` and `max-delay` are advertised together as a single Min/Max
attribute and are emitted only when **both** are set — a half-populated
bound would be a meaningless wire artifact. Statically configured values
carry a clear Anomalous flag.

### OSPFv3

Identical to OSPFv2, under `router ospfv3`:

```
router ospfv3 {
  area 0 {
    interface eth1 {
      te-metric {
        unidirectional-delay 1000;
        min-delay 900;
        max-delay 1200;
        delay-variation 50;
        loss 0;
      }
    }
  }
}
```

The leaves, ranges and units are the same as the OSPFv2 table above —
the values are shared, and only the wire code points differ.

### Measured delay (`te-metric measurement`)

To measure a link instead of pinning its values, enable the prober on
the interface. The measured min/max/avg/variation then populate the same
`te-metric` fields and are re-originated each time the damped value
moves:

```
router isis {
  interface eth1 {
    network-type point-to-point;
    te-metric {
      measurement {
        enabled true;
        interval 100;        # probe TX interval, ms  (100..60000, default 1000)
        damping-period 2;    # export window, seconds  (1..3600, default 30)
      }
    }
  }
}
```

OSPFv2 takes the identical block, one level deeper under `area / interface`
(and, as with static `te-metric`, only originates the result when SR-MPLS
is enabled — see the note under [Wire encoding](#ospfv2-rfc-7471)).

How the session is formed:

- **One session per link.** Both ends must enable `measurement` — a node
  reflects a probe only from a link on which it too is measuring (the
  implicit Session-Reflector, no separate reflector config). The session
  is created when the adjacency comes **Up** and torn down when it drops;
  a torn-down session clears its measured fields so a stale delay is
  never left advertised.
- **Point-to-point only**, and the address pair is chosen the way BFD
  chooses one: **prefer the IPv4 pair; fall back to the IPv6 link-local
  pair** when the link has no shared IPv4. So a dual-stack link is
  measured over IPv4, and a **v6-only IS-IS link is measured over its
  `fe80::` link-locals** (scoped by the interface) — either way it is one
  session feeding the same `te-metric`.
- **Probe TTL/Hop-Limit is 255** and the admission gate is the
  reflector's implicit allow-list, not a hop check.

Defaults (`interval` 1000 ms, `damping-period` 30 s) match the
periodic-advertisement cadence of IOS-XR / SR-OS; the lab values above
(100 ms / 2 s) converge in seconds.

### Measured loss (`te-metric measurement loss`)

The same session also measures **probe loss**, and the IGP advertises
it as the unidirectional link-loss sub-TLV (IS-IS 36, OSPFv2 30,
OSPFv3 16). This is **on by default wherever `measurement` is
enabled**, as on Cisco IOS XR. That means an upgrade adds a loss
sub-TLV to every measured link: 0 % on a clean link, about 120 seconds
after its session comes up. Turn it off per link with
`loss { enabled false; }`.

How it is measured:

- **Every probe is settled once**, by its sequence number: received when
  its reply is read within 3 seconds (RFC 7680's waiting time), lost
  otherwise. A reply that arrives later still counts as lost. A reply
  whose timestamps are rejected as a delay sample still counts as
  received — a clock fault is not packet loss.
- **Round-trip by default.** A stateless reflector copies the sender's
  sequence number, so a lost probe and a lost reply look the same, and
  the advertised value is round-trip loss — an upper bound on the
  forward loss the sub-TLV describes. Against a stateful reflector,
  forward loss can be advertised instead (see *Direction* below).
- **Averaged over the loss interval** (default 120 s), counted in
  30-second buckets on the session's own clock, independent of
  `damping-period`. The smallest step the value can take is one probe:
  0.83 % at the default 1 s probe interval over 120 s, 0.083 % at 100 ms.

```
te-metric {
  measurement {
    enabled true;
    reflector stateful;             # optional: reflect with our own sequence
                                    #   counter (default stateless)
    loss {
      enabled true;                 # default true
      interval 120;                 # seconds, a multiple of 30 (30..3600)
      threshold 10;                 # re-advertise on a change of this % of the value…
      minimum-change 1.0;           # …and of at least this many percentage points
      accelerated-threshold 5.0;    # optional: advertise at once when the latest
                                    #   30 s differs by this many points (default off)
      integrity 90;                 # % of expected probes a window needs
      anomaly-threshold 5.0;        # optional: set the A bit at or above this %
      reuse-threshold 1.0;          # …and clear it after an interval below this %
      peer-reflector stateful;      # optional: the peer reflects statefully, so
                                    #   advertise forward loss (default stateless)
    }
  }
}
```

The commit rejects a loss `interval` that is not a multiple of 30, and a
loss percentage (`minimum-change`, `accelerated-threshold`,
`anomaly-threshold`, `reuse-threshold`) over 100 or with more than six
decimal places, naming the offending line. Nothing is rounded.

When a value is advertised:

- **Not until a full, trustworthy window.** The window must be complete,
  and at least `integrity` % of the probes the probe interval should have
  produced must have settled. Before that, a static `te-metric loss` is
  advertised if one is configured, and nothing otherwise.
- **The first value goes out at once.** After that, a change is
  re-advertised at most once per loss interval (measured from the last
  advertisement), and only when it is at least
  `max(threshold % × advertised value, minimum-change)`. The
  default minimum change of 1.0 point is larger than one probe's worth at
  the default rate, so a single stray lost probe does not re-flood the
  LSP. To see finer loss, raise the probe rate *and* lower
  `minimum-change` together.
- **Silence withdraws, and is not counted as loss.** If a whole 30-second
  bucket goes by with probes sent but not one reply while the adjacency
  is up, the loss is withdrawn at once, not advertised as the
  50.331642 % maximum. That is a measurement problem — a reflector not
  running, an ACL, a policer on the probe DSCP — and advertising the
  maximum would make every Flex-Algo loss constraint prune a link that
  is forwarding traffic. Silent buckets are also left out of the window
  as gaps, so once replies return, nothing is advertised until the
  window has refilled with real measurements. (A bucket needs at least
  10 probes to count as silent; at slow probe rates, all of a few probes
  being lost is ordinary loss.)
- **The Anomalous (A) bit is opt-in.** With `anomaly-threshold` set, the
  bit is set on the link-loss sub-TLV as soon as the value it is
  advertised with reaches the bound. That value is the one in the
  sub-TLV: with acceleration on, an accelerated 10 % carries the bit
  against a 5 % bound even though the rolling average is lower. The
  bound is compared with the measured loss exactly, so it works above
  the 50.331642 % the sub-TLV can carry — 80 % loss against a 60 % bound
  advertises the maximum with the bit set — and at bounds finer than the
  sub-TLV's 0.000003 % unit. A change
  of the bit is advertised at once, with its value, whatever the
  interval and threshold would otherwise hold back. The bit clears only
  once the loss has stayed below `reuse-threshold` (default: the anomaly
  bound) for a whole loss interval; any evaluation back at or above the
  reuse bound restarts that wait (RFC 8570 §5, "below … for one or more
  advertisement intervals"). A withdrawal forgets the bit: a value that
  comes back after silence has to cross the bound again.
- **A static `te-metric loss` always wins** over the measured value, and
  is always advertised with the A bit clear.

#### Direction: forward loss against a stateful reflector

By default the advertised loss is round-trip, because a stateless
reflector (RFC 8762 §4.3) copies the sender's sequence number: a lost
probe and a lost reply look the same. A *stateful* reflector puts its
own per-peer counter in every reply instead, and that tells the two
apart. Between two replies that did come back, the counter says how many
of the probes in between reached the reflector: those were lost on the
way back, and the rest on the way out.

Two zebra-rs routers get forward loss by setting both ends:

- `measurement reflector stateful` on the router that reflects: it
  answers this link's peer with its own counter. It is on if any IGP
  measuring the link sets it, so a second IGP left at the default does
  not turn it off.
- `loss peer-reflector stateful` on the router that measures: the peer
  reflects statefully, so advertise forward loss. A Juniper peer with
  `stateful-sequence` counts as stateful.

The peer's mode is **declared, not detected**: a stateless reflector with
forward loss and a stateful one with reverse loss send exactly the same
replies. Declaring a stateless peer stateful makes every loss read as
reverse, and the advertised forward loss as zero. Changing
`peer-reflector` starts that IGP's loss advertisement over: the new value
goes out at once, not filtered against a value of the other kind.

Losses are split once each gap of consecutive lost probes has closed,
which happens when the next reply arrives. Until then they are
*unresolved* and counted as forward: the value errs high, never low. A
gap the counter cannot explain stays unresolved: the peer restarted, its
counter moved backwards, or probes were reordered across the gap. `show
stamp session` gives each such IGP's split:

```
                loss: advertised 0.000000% forward (interval 30s, threshold 10%, minimum-change 0.999999%, integrity 90%, peer-reflector stateful)
                  direction over 30s: forward 0, reverse 30, unresolved 0 of 300 probes
```

The loss settings belong to each IGP. IS-IS and OSPF measuring the same
link share one session and one set of buckets, but each applies its own
`loss` settings: turning loss off in IS-IS leaves OSPF advertising it.
`show stamp session` lists each IGP's policy and what it currently
advertises:

```
        Subscribers:
            isis: anomaly-threshold none, Anomalous: avg no, min no, max no
                loss: advertised 0.000000% (interval 120s, threshold 10%, minimum-change 0.999999%, integrity 90%)
```

The advertised value and the change thresholds are shown in the
sub-TLV's own units of 0.000003 %, so a configured 1.0 % reads
0.999999 %. Anomaly bounds are kept as configured and print exactly.
With them configured the line lists them, and an advertisement carrying
the A bit is marked `(A)`, as in `show isis database detail`:

```
                loss: advertised 9.999999% (A) (interval 120s, threshold 10%, minimum-change 0.999999%, integrity 90%, anomaly 5.000000%, reuse 1.000000%)
```

## Wire encoding

### IS-IS (RFC 8570)

The metrics are sub-TLVs of the Extended IS Reachability TLV (TLV 22,
and the MT IS Reach TLV 222 when multi-topology is enabled):

| Sub-TLV | Code | RFC |
|---|---|---|
| Unidirectional Link Delay | 33 | RFC 8570 §4.1 |
| Min/Max Unidirectional Link Delay | 34 | RFC 8570 §4.2 |
| Unidirectional Delay Variation | 35 | RFC 8570 §4.3 |
| Unidirectional Link Loss | 36 | RFC 8570 §4.4 |

They are advertised in **two places at once**:

- **Inline** in the reach entry, for general (non-Flex-Algo) TE
  visibility and any consumer reading the legacy attributes directly.
- **Nested in the Flex-Algorithm ASLA** (Application-Specific Link
  Attributes, sub-TLV 16, RFC 9479) with the SABM X-bit set. RFC 9350
  §6.3 requires the attributes a Flex-Algorithm consumes to be
  application-scoped, so the inline copy alone is not enough — the ASLA
  copy is what SPF reads.

### OSPFv2 (RFC 7471)

OSPFv2 has no legacy TE Opaque LSA in zebra-rs, so the metrics live only
in the ASLA sub-sub-TLVs (RFC 9492) of the Extended-Link Opaque LSA —
the same place per-link Flex-Algo affinity is carried:

| Sub-sub-TLV | Code | RFC |
|---|---|---|
| Unidirectional Link Delay | 27 | RFC 7471 §4.1 |
| Min/Max Unidirectional Link Delay | 28 | RFC 7471 §4.2 |
| Unidirectional Delay Variation | 29 | RFC 7471 §4.3 |
| Unidirectional Link Loss | 30 | RFC 7471 §4.4 |

The wire shapes are byte-identical to the IS-IS sub-TLVs above (a 1-bit
Anomalous flag and a 24-bit value, in microseconds); only the code
points differ.

### OSPFv3 (RFC 7471 values, OSPFv3 code points)

OSPFv3 carries the same four attributes in the ASLA of its E-Router-LSA
(RFC 8362) Router-Link TLV. The *values* are the RFC 7471 encodings
unchanged — same Anomalous bit, same 24-bit fields — but the code points
come from the OSPFv3 Extended-LSA sub-TLV registry, not the OSPFv2 TE
Opaque LSA one:

| Sub-sub-TLV | OSPFv3 code | OSPFv2 code |
|---|---|---|
| Unidirectional Link Delay | 13 | 27 |
| Min/Max Unidirectional Link Delay | 14 | 28 |
| Unidirectional Delay Variation | 15 | 29 |
| Unidirectional Link Loss | 16 | 30 |

> **Segment Routing is not required.** Both LSAs that carry the ASLA —
> the OSPFv2 Extended-Link Opaque LSA and the OSPFv3 E-Router-LSA — used
> to be originated only when SR was enabled, which meant configuring
> `te-metric` without SR advertised nothing at all, silently. SR now
> gates the Adj-SID and End.X contributions to those LSAs rather than
> the LSAs themselves, so `te-metric` works on its own. All three IGPs
> now behave the same way.

## Flexible Algorithm consumption

A Flexible Algorithm Definition selects its metric with `metric-type`.
Metric-type 1 (`min-unidir-link-delay`, RFC 9350 §5.1) makes the per-algo
SPF route on delay:

```
router isis {
  flex-algo 128 {
    metric-type min-unidir-link-delay;
    advertise-definition true;
  }
}
```

When an algorithm uses metric-type 1, each link's edge cost is its
**Min delay** (the Min field of the Min/Max attribute), not the IGP
metric:

- A router's own links take the value from local `te-metric` config.
- Remote links take it from the link's Flex-Algo ASLA.
- A link that advertises **no** delay is **pruned** from that
  algorithm's topology (RFC 9350 §15 — a link missing the selected
  metric MUST NOT be used).

Algorithm 0 (the default SPF) and any algorithm using metric-type 0
(IGP) are unaffected; they continue to use the configured interface
cost. The TE-default metric-type (2) is not supported: a winning
definition asking for it stops participation.

Measured loss feeds a constraint rather than a metric. An IS-IS
algorithm whose definition carries `exclude-max-link-loss` prunes every
link whose advertised loss exceeds it, and keeps links that advertise
none — see [Link loss](ch-07-11-isis-flexalgo.md#link-loss). The loss
settings above are what keep such a topology stable: pruning itself is
never damped.

## Verifying

The advertised metrics appear in the link-state database dumps:

- `show isis database` renders the RFC 8570 sub-TLVs (inline and inside
  the ASLA) on each reach entry.
- `show ospf database detail` renders the ASLA sub-sub-TLVs on the
  Extended-Link Opaque LSA.

The per-algorithm result — including the metric-type and the
delay-weighted shortest paths — is shown by:

- `show isis flex-algo`
- `show ospf flex-algo`

The measurement plane has its own show commands:

- `show stamp` — one line per session: the link, the remote address
  (an `fe80::` link-local on a v6-only link), sender state, and the
  latest damped delay.
- `show stamp session` — per-session detail (SSID, timing parameters,
  the min/max/avg/variation window, packet counts).
- `show stamp statistics` — sender and reflector packet counters,
  including how many receive timestamps came from the kernel
  (`SO_TIMESTAMPING`) versus a userspace read.

## The measurement plane

The active prober runs as a **separate task**, spawned like BFD and
Neighbor Discovery rather than living inside the IGP tasks — performance
measurement is its own subsystem that hands results to the IGP, never
the reverse. The IGPs (un)subscribe a per-link session as adjacencies
come and go; the prober owns the sockets, the timing, and the damping.

Its building blocks:

- **Protocol** — STAMP (RFC 8762): a 44-octet Session-Sender packet and
  a Session-Reflector that timestamps and returns it. zebra-rs runs an
  unauthenticated Session-Sender per measured link and an *implicit*
  Session-Reflector on UDP 862 (both `0.0.0.0` and `[::]`) that answers
  a probe only from a link it is itself measuring. STAMP is
  wire-compatible with unauthenticated TWAMP Light peers (RFC 8762 §4.6),
  so a zebra-rs reflector interoperates with an IOS-XR TWAMP-Light sender
  and a Nokia STAMP sender alike. The optional TLVs (RFC 8972) and the SR
  return-path TLVs (RFC 9503) extend it for segment-routed measurement.
- **Delay math** — each reflected packet carries four timestamps, and
  the one-way delay is `((T4 − T1) − (T3 − T2)) / 2`. Because the two
  same-clock differences (`T4 − T1` on the sender, `T3 − T2` on the
  reflector) are subtracted, the clock offset between the two systems
  cancels — no time synchronization is required. Samples that compute
  negative or implausibly large (a wall-clock step mid-probe) are
  discarded and counted.
- **Timestamping** — the receive timestamps T2 (reflector) and T4
  (sender) are taken by the kernel via `SO_TIMESTAMPING` (software RX),
  not a post-wakeup userspace read, so the reported delay excludes the
  daemon's own scheduling latency. Software stamps are stack-level and
  so work on every interface including veth/loopback; `show stamp
  statistics` reports how often the kernel stamp was used. (Software *TX*
  timestamps are not available on virtual interfaces, so T1 is stamped in
  userspace at build time.)
- **Codec** — the `stamp-packet` crate implements the packet and TLV
  encode/decode (sender/reflector base, error-estimate, the RFC 8972 TLV
  framework, and the RFC 9503 return-path sub-TLVs).
- **Damping** — the measured value feeds the IGP only after rolling
  averaging plus threshold/periodic suppression, so a noisy probe stream
  does not re-originate an LSP/LSA on every packet. Each export window
  re-advertises only if a field moved beyond a small threshold; an empty
  window clears the measured values. This mirrors the
  periodic-plus-accelerated advertisement model of IOS-XR and SR-OS and
  is essential: without it, delay measurement would thrash the flooding
  domain.

The prober is the second writer of the per-interface `te-metric` fields
documented above; everything downstream — origination, the ASLA,
Flex-Algorithm SPF — is the same code the static path uses, unchanged.
