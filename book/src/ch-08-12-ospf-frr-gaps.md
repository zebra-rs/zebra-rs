# Gaps Relative to FRR ospfd

OSPFv2 features not yet implemented in zebra-rs:

- Virtual links across non-backbone areas.
- Area ranges (`area <id> range` Type-3 summary aggregation and
  suppression at the ABR).
- Passive interfaces (advertise a prefix without forming
  adjacencies on it).
- Instance-level `default-information originate` (Type-5 default
  route). The NSSA-scoped Type-7 default
  (`nssa-default-originate`) is implemented.
- NBMA and point-to-multipoint network types — the per-interface
  `network-type` knob accepts `broadcast` and `point-to-point`
  only.
- Stub-router advertisement (`max-metric router-lsa`, RFC 6987).
- Redistribution `route-map` filtering and the `table` source (the
  zebra-rs sources are connected, static, kernel, IS-IS, and BGP).
- Forwarding-address resolution on received externals: Type-5/
  Type-7 LSAs carrying a non-zero forwarding address are skipped
  (RFC 2328 §16.4 step 3); zebra-rs itself always originates with
  FA 0.0.0.0.
- Configurable SPF / LSA-generation throttles. SPF is coalesced
  behind a fixed 1-second timer (an LSDB change arms it; further
  changes within the window ride the same run), but the adaptive
  initial/secondary/maximum-wait throttle that FRR
  (`timers throttle spf`) and zebra-rs IS-IS (`spf-interval`)
  expose is not configurable for OSPF.

## Previously listed gaps that are now closed

Earlier revisions of this book listed the following as missing;
all have since been implemented for OSPFv2 (OSPFv3 coverage varies
per feature — see each feature's page):

- **Stub / NSSA / Totally-Stubby area types** (RFC 2328 §3.6,
  RFC 3101) — `area-type stub | nssa` plus `no-summary`
  (totally-stubby / totally-NSSA), `nssa-default-originate`,
  `nssa-suppress-fa`, and `nssa-translator-role` with RFC 3101
  §2.2 Candidate translator election and Type-7→Type-5
  translation at the NSSA ABR. Implemented for both OSPFv2 and
  OSPFv3. See [Area Types](ch-08-13-ospf-area-types.md).
- **ABR Type-3 (Summary) and Type-4 (ASBR-Summary) origination**,
  including cross-area E1/E2 external-route computation and
  Type-4 fallback for inter-area ASBR resolution. v2 only —
  OSPFv3 ABR summary origination is still pending. See
  [Multi-Area Routing and the ABR](ch-08-14-ospf-multi-area-abr.md).
- **Type-5 (AS-External) origination from redistribution** and
  **Type-7 (NSSA-External) translation**. See
  [Route Redistribution](ch-08-15-ospf-redistribution.md).
- **Per-interface authentication** — simple password, MD5
  `message-digest-key`, cryptographic HMAC-SHA authentication
  (RFC 5709), RFC 8177 key-chains, and the OSPFv3 Authentication
  Trailer (RFC 7166). See
  [Authentication](ch-08-16-ospf-authentication.md).
- **Graceful Restart** (RFC 3623) — helper mode (Grace-LSA
  acceptance with optional strict-LSA-checking) and restarter
  mode backed by an on-disk LSDB checkpoint; OSPFv3 is
  helper-only. See
  [Graceful Restart](ch-08-17-ospf-graceful-restart.md).
