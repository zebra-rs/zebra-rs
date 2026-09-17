# IS-IS RFC8570 and OSPF RFC7471 implementation status

Reviewed on 2026-09-16 against [the STAMP/IGP integration design](../design/stamp-isis-ospf.md), the current source, and the packet tests. This is an implementation status review, not a complete RFC conformance audit.

**Status update (2026-09-16).** Sequencing step 1 below — Anomalous bit
origination with configurable thresholds — has since been implemented on
branch `stamp-te-anomalous-bit` (`596416bf`, `666b417d`, `4c562c24`). The
capability table, the anomaly bullets under "Advertisement stability", and
step 1 are marked accordingly; everything else is as first reviewed.

## Result

Measured against the three layers in the stamp document:

- **Pattern A (link PM feeding IGP TE metrics)** is implemented on all three IGPs — IS-IS, OSPFv2 and OSPFv3 — for STAMP-derived delay advertisement and Flex-Algo min-delay SPF. Neither RFC is fully implemented end to end: loss is never measured and the bandwidth attributes are absent or originate nowhere.
- **Pattern B (IGP auto-discovery of STAMP endpoints)** is absent. Sessions are derived from IGP adjacency state instead of from flooded measurement-group membership.
- **Pattern C (consumers of the flooded metrics)** is limited to Flex-Algo metric-type 1. BGP-LS export and SR path PM are not wired up.

| Capability | IS-IS RFC8570 | OSPF RFC7471 |
|---|---|---|
| Average delay, min/max delay, delay variation, loss codecs | Implemented: sub-TLVs 33–36 | Implemented: sub-TLVs 27–30 |
| Residual, available, utilized bandwidth codecs | Implemented: sub-TLVs 37–39 | No typed support found |
| Static delay/loss configuration | Implemented | OSPFv2 only |
| Metric advertisement | Inline TLV 22/222 and Flex-Algo ASLA | ASLA in the OSPFv2 Extended-Link Opaque LSA and the OSPFv3 E-Router-LSA; no Segment Routing required |
| STAMP feeding advertised delay metrics | P2P, IPv4 or IPv6 | OSPFv2 P2P, IPv4 |
| Anomalous bit origination | Implemented; per-value bits, per-IGP thresholds | Implemented; per-value bits, per-IGP thresholds |
| Flex-Algo min-delay SPF | Implemented | Implemented on both versions |
| STAMP endpoint auto-discovery (AMG) | Not implemented | Not implemented |
| BGP-LS export of measured metrics | Not implemented | Not implemented |

## Implemented paths

### IS-IS

- [Packet codecs](../../crates/isis-packet/src/sub/neigh.rs) parse and emit all seven RFC8570 metrics, including Anomalous flags where defined and IEEE 754 bandwidth values.
- [Per-interface metric configuration and builders](../../zebra-rs/src/isis/link.rs) support average delay, minimum delay, maximum delay, variation, and raw encoded loss. Min/max is emitted only when both bounds are present.
- [LSP origination](../../zebra-rs/src/isis/lsp.rs) advertises delay/loss inline in Extended IS Reachability TLV 22 and MT IS Reachability TLV 222, with an additional application-specific copy for Flex-Algo.
- [STAMP integration](../../zebra-rs/src/isis/inst.rs) subscribes enabled P2P links with an Up adjacency, using interface/neighbor IPv4 addresses or IPv6 link-local addresses. Updates populate measured delay fields and trigger re-origination. Session teardown clears measured values.
- [Flex-Algo graph construction](../../zebra-rs/src/isis/graph.rs) uses minimum delay for metric-type 1. Peer delay comes from ASLA; local delay comes from effective per-link metrics. Links without delay are pruned.

### OSPFv2

- [Packet codecs](../../crates/ospf-packet/src/parser.rs) support delay/loss types 27–30 inside ASLA in Extended-Link LSAs.
- [Configuration](../../zebra-rs/src/ospf/config.rs) and [per-interface metric builders](../../zebra-rs/src/ospf/link.rs) support the same five configurable fields as IS-IS.
- [Instance integration and origination](../../zebra-rs/src/ospf/inst.rs) subscribe enabled IPv4 P2P links with a Full adjacency, apply measured snapshots, and refresh Extended-Link Opaque LSAs. Origination no longer requires SR-MPLS: Segment Routing gates the Adj-SID contributions to that LSA, not the LSA itself.
- Flex-Algo metric-type 1 reads minimum delay from advertised ASLA and uses it as the SPF edge cost.

For both protocols, static configuration overrides measured values per field. Unconfigured fields use the measurement.

On the receive side, only the application-specific copy feeds routing. IS-IS reads a peer's minimum delay from the ASLA sub-TLV; the inline TLV 22/222 copy is decoded and displayed but never consulted by SPF. A peer that advertises delay inline only — without ASLA — is therefore pruned from a metric-type-1 topology.

That pruning is correct, not a gap. RFC 9350 §12 requires Flex-Algorithm link attributes to come from an ASLA advertisement "unless, in the case of IS-IS, the L-flag is set", so a peer that never emits an ASLA has advertised no Flex-Algorithm delay, and every conformant router in the domain prunes that link identically. An earlier revision of this review recommended adding a legacy fallback; that recommendation was wrong and is withdrawn — see the correction below.

## Remaining gaps against the stamp document

### Measurement and metric coverage

1. **True one-way delay:** [STAMP delay calculation](../../zebra-rs/src/stamp/inst.rs) uses `((T4 - T1) - (T3 - T2)) / 2`. This removes reflector residence time but still approximates forward delay by assuming symmetric paths; it is not synchronized one-way measurement.
2. **Measured loss export:** [STAMP statistics](../../zebra-rs/src/stamp/stats.rs) count sent/received probes for display, but explicitly exclude loss from IGP exports. Static loss advertisement exists.
3. **Bandwidth integration:** IS-IS packet codecs exist, but its per-interface metric model has no residual/available/utilized bandwidth fields. OSPF has no typed support for the corresponding bandwidth metrics. STAMP itself is not the source of these bandwidth values.
4. **OSPF carriers:** The implemented OSPFv2 path is application-specific Extended-Link advertisement. The classic TE Opaque LSA Link TLV path described in the stamp document is absent.
5. ~~**OSPFv3:** no `te-metric` configuration, IPv4-only STAMP address selection, and a Flex-Algo graph costing on the IGP metric.~~ **Delivered** (#2387): the full config tree under `router ospfv3`, IPv6 link-local STAMP sessions, origination into the E-Router-LSA ASLA at OSPFv3 code points 13-16, and metric-type-1 SPF with RFC 9350 §15 pruning.
6. **Circuit types:** Measurement is gated on a P2P circuit in both IGPs, so broadcast/LAN adjacencies are never measured — a LAN link can only carry statically configured metrics.
7. **LAG member measurement:** [RFC9534](https://www.rfc-editor.org/rfc/rfc9534.html) micro-sessions are not implemented; there is no per-member session model, so a bundle is measured as one link or not at all.

### Advertisement stability and anomaly behavior

[STAMP statistics](../../zebra-rs/src/stamp/stats.rs) average samples within each export window and compute min/max and mean absolute consecutive-sample variation. Windows reset after each export tick; this is window averaging rather than a rolling average across windows.

[Export damping](../../zebra-rs/src/stamp/damping.rs) exports the first snapshot, withdraws a previously exported value when a window is empty, and exports subsequent snapshots only when any field moves by more than `max(previous / 10, 50 microseconds)`. The [default timing](../../zebra-rs/src/stamp/session.rs) is one probe per second and a 30-second export window; probe/export intervals can be configured.

The following remain missing:

- Configurable percentage/absolute change thresholds for the *value* filter; those remain fixed constants. (The separate anomaly and reuse bounds are now configurable — see the status update.)
- A periodic re-advertisement timer that refreshes an unchanged value; export is threshold-driven only. Severity is limited: both IGPs re-run origination from live link state on self-originated refresh ([`ext_link_lsa_originate`](../../zebra-rs/src/ospf/inst.rs) for OSPF, `LspOriginate` rebuilding TLVs from `top.links` for IS-IS), so ordinary LSP/LSA refresh already re-floods the current measured value. Staleness is bounded by the refresh interval rather than unbounded.
- An accelerated advertisement path for large changes between periodic export ticks.
- Interval-based hysteresis — "hold the bit for N periods". The implemented hysteresis is the band between the anomaly and reuse bounds, which is the RFC's own mechanism; a period-count qualifier on top of it is not implemented.
- Anomaly-driven IGP/TE cost fallback.

Since implemented (see the status update): configurable upper anomaly and
reuse bounds, and origination of the Anomalous bit on threshold crossing.
The bit is evaluated per advertised value — the average drives sub-TLV
33/27, the two bounds jointly drive 34/28 — and per subscribing IGP, since
IS-IS and OSPF share one STAMP session but configure the policy separately.

These integration gaps should be distinguished from RFC distribution requirements: [RFC8570](https://www.rfc-editor.org/rfc/rfc8570.html) and [RFC7471](https://www.rfc-editor.org/rfc/rfc7471.html) define performance-information distribution; measurement and routing actions are outside their scope.

### Pattern B — IGP auto-discovery of STAMP endpoints

Nothing from [draft-admnr-lsr-igp-measurement-group](https://datatracker.ietf.org/doc/draft-admnr-lsr-igp-measurement-group/04/) is implemented:

- [IS-IS Router CAPABILITY sub-TLV codes](../../crates/isis-packet/src/sub/cap_code.rs) have no AMP Measurement Group entry; such a sub-TLV decodes as unknown.
- No corresponding Router Information LSA TLV exists on the OSPF side.
- There is no Group ID configuration, no endpoint-set model, and no higher-IP tie-break for two-sided session initiation.

Session targets come from IGP adjacency state instead — interface/neighbor addresses on an enabled P2P link. That covers the per-link case the draft's physical-interface endpoints target, so the practical shortfall is loopback-to-loopback meshes, which still require explicit per-session configuration or an external NMS. The draft is individual, not WG-adopted, so this is a watch item rather than a conformance gap.

### Pattern C — consumers of the flooded metrics

- **Flex-Algo min-delay:** implemented on both IGPs, as described above.
- **Flex-Algo link loss:** [draft-ietf-lsr-flex-algo-link-loss](https://datatracker.ietf.org/doc/html/draft-ietf-lsr-flex-algo-link-loss) is not implemented; there is no loss-threshold exclusion in either Flex-Algo graph builder, and loss is not measured in the first place.
- **BGP-LS (updated 2026-09-16):** the [IS-IS BGP-LS translation](../../zebra-rs/src/isis/bgp_ls.rs) now supports RFC8571 performance TLVs 1114–1120 and RFC9294 application-specific attributes in TLV 1122. These attributes reach the local BGP-LS RIB. Transmission to external BGP-LS peers remains unimplemented in [`route_bgpls_originate`](../../zebra-rs/src/bgp/route.rs), so delivery to a PCE or controller is still unverified. The BDD topology checks remote IS-IS flooding followed by local translation, not BGP UPDATE delivery; see the [BGP-LS review](bgp-ls-te-performance-2026-09-16.md).
- **SR path PM:** the [STAMP TLV framework](../../crates/stamp-packet/src/tlv.rs) and [return path encoding](../../crates/stamp-packet/src/return_path.rs) implement the RFC8972 TLV shape plus the RFC9503 Destination Node Address and Return Path TLVs, but no daemon code constructs them. This is codec-only support with no path-measurement driver.
- **RSVP-TE / SR-TE CSPF:** not applicable; there is no CSPF consumer in this codebase.

### Documentation

The [supported-RFC appendix](../../book/src/appendix-b-supported-rfcs.md) lists RFC7471 and RFC8570 with the qualifier "unidirectional delay / loss", which correctly excludes the bandwidth sub-TLVs, but does not record that RFC7471 support is OSPFv2-only.

## Recommended sequencing

Ordering rationale: finish what the two RFCs themselves define before extending coverage, and prefer work that lands once in the shared STAMP layer over work that must be written twice.

### 1. Anomalous bit origination and configurable thresholds — DELIVERED

Implemented on `stamp-te-anomalous-bit`. The three design decisions called
out below were all load-bearing, and two more surfaced in review: a
flag-only export must advance the cache a late subscriber is seeded from,
and a params-only config edit must re-subscribe in place rather than
unsubscribe, or it discards the hysteresis and silently clears a standing
bit. The original reasoning is kept below as written.

The only remaining piece of the RFC8570 §5 / RFC7471 §5 advertisement contract. Both metric builders currently hard-code `anomalous: false`, so the daemon asserts "not anomalous" without ever evaluating the condition. Every other gap is either outside the RFCs (measurement quality, cost fallback) or a coverage extension (OSPFv3 — since delivered — bandwidth, LAN).

Structurally cheap, because the measurement side is already shared: thresholds extend the existing `MeasurementConfig`, detection lands in [damping](../../zebra-rs/src/stamp/damping.rs), and each IGP needs only a small plumb into its `sub_tlvs()` / `asla_sub_subs()` builder. One change covers both protocols.

Design decisions to settle first:

- **The bit is per sub-TLV, not per link.** Delay, min/max and loss each carry their own Anomalous flag; delay variation has none. `LinkTeMetric` is a flat struct whose `merged_over` mixes static and measured values *per field*, so a single struct-level `anomalous` flag would be wrong. A statically configured field must always originate clear — an anomaly cannot be asserted for a value that was never measured.
- **The damping gate will otherwise suppress the anomaly.** `should_export` fires only on movement past `max(previous / 10, 50 microseconds)`. A link that degrades and stays degraded crosses once and then settles, so a later Anomalous transition whose value delta is under the threshold would never be exported. Both the set and the clear transition must force an export independently of the value delta.
- **Anomaly is not withdrawal.** An empty window exports `None`, which withdraws the sub-TLVs and prunes the link from metric-type-1 SPF. An anomalous link keeps advertising with the bit set. The two paths must stay distinct.

Anomaly-driven IGP/TE cost fallback is a routing action outside both RFCs; it belongs in a follow-on, once the bit is trustworthy.

### 2. BGP-LS performance TLVs — LOCAL TRANSLATION DELIVERED; PEER TRANSMISSION PENDING

The performance TLVs and application-specific translation are implemented in [`link_attr`](../../zebra-rs/src/isis/bgp_ls.rs). The remaining step for controller delivery is outbound BGP-LS advertisement to external peers. Validate that path by receiving BGP UPDATEs on a peer and decoding the performance attributes and TLV 1122 application masks. Local RIB display and IS-IS round-trip tests do not establish controller delivery.

### 3. OSPFv3 TE metrics — DELIVERED (#2387)

The largest remaining asymmetry: an IPv6-only fabric can measure and advertise delay through IS-IS today, but has nowhere to publish it on the OSPF side. Largest single item, though nearly all of it mirrors existing v2 and IS-IS code. Components: delay/loss variants in `Ospfv3AslaSubSubTlv`, `te-metric` registration in [config_v3.rs](../../zebra-rs/src/ospf/config_v3.rs), origination into the E-Router-LSA ASLA, IPv6 pair support in `stamp_reconcile_link` (which currently accepts IPv4 pairs only — the IS-IS v4-preferred / v6-link-local rule is the model), and the delay join in the v3 Flex-Algo graph.

### 4. Measured loss

Requires a rolling multi-window loss estimator; a single export window is too noisy to advertise, as the original design plan records. Unblocks a measured source for sub-TLV 36/30 and makes [draft-ietf-lsr-flex-algo-link-loss](https://datatracker.ietf.org/doc/html/draft-ietf-lsr-flex-algo-link-loss) implementable.

### Correction — the "receive-side fallback" recommendation was wrong

An earlier revision of this section recommended, as an easy interoperability win, falling back to a peer's inline delay sub-TLV when it advertises no ASLA. **Do not do this.** RFC 9350 §12 permits legacy sourcing for Flex-Algorithm only when an applicable ASLA sets the IS-IS L-flag; the absence of an ASLA is not that signal. A router that accepted the legacy value anyway would compute a shorter edge for that link than every conformant neighbour does, which is how a delay-based topology ends up with inconsistent paths.

The fallback was briefly implemented on that recommendation and then removed. What replaced it is the actual RFC 9479 §4.2 selection, which the original ASLA-only code also lacked: an explicit X-bit advertisement wins; failing that a zero-length-mask advertisement applies; the applicable ASLA's L-flag then decides between its nested attributes and the legacy ones; and no applicable ASLA means no Flex-Algorithm delay. See `isis::flex_algo::peer_min_delay`.

### Deferred

- **LAN circuits** need a design decision first: the IS-IS pseudonode model has no per-neighbor TLV 22 entry on which to hang a per-neighbor delay.
- **Bandwidth sub-TLVs** need an interface-utilization source and are not STAMP-derived.
- **RFC9534 LAG micro-sessions, AMG discovery (Pattern B), and SR path PM** are separate features rather than completions of this integration.

## Validation

Ran successfully:

```sh
cargo test -p isis-packet -p ospf-packet
```

This includes the RFC8570 performance-metric round-trip test in [IS-IS packet tests](../../crates/isis-packet/tests/json.rs), and OSPF ASLA delay/loss round-trip and field-masking tests in [parser.rs](../../crates/ospf-packet/src/parser.rs). The command completed with no failures; some existing tests are ignored.

Existing BDD coverage includes:

- [stamp_te_metric.feature](../../bdd/tests/features/stamp_te_metric.feature): shared IS-IS/OSPFv2 IPv4 P2P STAMP sessions and measured LSDB delay advertisements, with SR-MPLS enabled for OSPF.
- [stamp_v6_te_metric.feature](../../bdd/tests/features/stamp_v6_te_metric.feature): IPv6-only IS-IS measurement and delay advertisement.

The BDD scenarios were inspected but not run during this review. Daemon-level tests, live interoperation, and full RFC conformance were not validated. No implementation source was changed.

The 2026-09-16 revisions that added the Pattern B, Pattern C, circuit-type, LAG, receive-side and documentation findings, the refresh-path qualification on periodic re-advertisement, and the sequencing section were source audits only; no tests were re-run for them. The sequencing reflects a judgement on ordering, not a validated implementation plan.
