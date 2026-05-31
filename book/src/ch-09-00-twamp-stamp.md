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

The **distribution and consumption planes are implemented** for both
IGPs, end to end:

| | Origination | Flex-Algo consumption (metric-type 1) |
|---|---|---|
| IS-IS | RFC 8570 sub-TLVs, inline + ASLA | yes |
| OSPFv2 | RFC 7471 attributes in ASLA | yes |

Today the metric values come from **static per-interface configuration**
(the `te-metric` block below). The **STAMP measurement runtime that
populates them dynamically is the next step** — see
[The measurement plane](#the-measurement-plane). Because both sides
share the `te-metric` fields, static configuration is a faithful
stand-in: a topology configured by hand behaves exactly as it will once
the prober feeds the same fields live.

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
carry a clear Anomalous flag; the measurement plane will raise it on a
threshold crossing.

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
- `show ip ospf database detail` renders the ASLA sub-sub-TLVs on the
  Extended-Link Opaque LSA.

The per-algorithm result — including the metric-type and the
delay-weighted shortest paths — is shown by:

- `show isis flex-algo`
- `show ip ospf flex-algo`

## The measurement plane

The active prober is a **separate task**, spawned like BFD and Neighbor
Discovery rather than living inside the IGP tasks — performance
measurement is its own subsystem that hands results to the IGP, never
the reverse.

Its building blocks:

- **Protocol** — STAMP (RFC 8762): a 44-octet Session-Sender packet and
  a Session-Reflector that timestamps and returns it, from which one-way
  or round-trip delay is derived. STAMP is wire-compatible with
  unauthenticated TWAMP Light peers (RFC 8762 §4.6), so a zebra-rs
  reflector interoperates with an IOS-XR TWAMP-Light sender and a Nokia
  STAMP sender alike. The optional TLVs (RFC 8972) and the SR return-path
  TLVs (RFC 9503 — Destination Node Address, Return Path) extend it for
  segment-routed measurement.
- **Codec** — the `stamp-packet` crate already implements the packet and
  TLV encode/decode (sender/reflector base, error-estimate, the RFC 8972
  TLV framework, and the RFC 9503 return-path sub-TLVs).
- **Damping** — the measured value feeds the IGP only after rolling
  averaging plus threshold/periodic suppression, so a noisy probe stream
  does not re-originate an LSP/LSA on every packet. This mirrors the
  periodic-plus-accelerated advertisement model of IOS-XR and SR-OS and
  is essential: without it, delay measurement would thrash the flooding
  domain.

When that task lands, it becomes a second writer of the per-interface
`te-metric` fields documented above; everything downstream — origination,
the ASLA, Flex-Algorithm SPF — is already in place and unchanged.
