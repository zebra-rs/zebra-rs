# Link Delay Measurement (TWAMP Light / STAMP)

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

> **OSPFv3** has no TE-metric origination, so there is nowhere to publish
> an IPv6 delay on the OSPF side; IPv6 measurement is therefore an IS-IS
> feature, riding the link's IPv6 link-local adjacency. OSPFv2 is
> IPv4-only on the wire. See [The measurement plane](#the-measurement-plane).

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
        enable true;
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

> **Note** — OSPFv2 originates the Extended-Link Opaque LSA only when
> Segment Routing over MPLS is enabled (`router ospf / segment-routing /
> mpls`). Because that LSA is where the ASLA — and therefore the
> metrics — ride, OSPF advertises `te-metric` only when SR-MPLS is on.
> This matches how Flex-Algo affinity is already gated and is the
> expected configuration for delay-based Flex-Algorithm.

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
cost. The TE-default metric-type (2) is not yet supported and falls back
to the IGP metric.

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
