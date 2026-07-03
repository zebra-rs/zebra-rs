# Gaps Relative to FRR ospfd

OSPFv2 features not yet implemented in zebra-rs:

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
  Type-4 fallback for inter-area ASBR resolution. Implemented for
  both OSPFv2 and OSPFv3 (v3 Inter-Area-Prefix 0x2003 /
  Inter-Area-Router 0x2004). See
  [Multi-Area Routing and the ABR](ch-08-14-ospf-multi-area-abr.md).
- **Discard (blackhole) routes for active area ranges**
  (RFC 2328 §12.4.3) — the loop-safety companion to range
  aggregation, installed via the RIB `nexthop blackhole` type for
  both OSPFv2 and OSPFv3. See
  [Multi-Area Routing and the ABR](ch-08-14-ospf-multi-area-abr.md#discard-route).
- **Type-5 (AS-External) origination from redistribution** and
  **Type-7 (NSSA-External) translation**. See
  [Route Redistribution](ch-08-15-ospf-redistribution.md).
- **Per-interface authentication** — simple password, MD5
  `message-digest-key`, cryptographic HMAC-SHA authentication
  (RFC 5709), RFC 8177 key-chains, and the OSPFv3 Authentication
  Trailer (RFC 7166). See
  [Authentication](ch-08-16-ospf-authentication.md).
- **Graceful Restart** — helper mode (Grace-LSA acceptance with
  optional strict-LSA-checking) and restarter mode backed by an
  on-disk LSDB checkpoint, in **both** roles for OSPFv2 (RFC 3623)
  and OSPFv3 (RFC 5187). See
  [Graceful Restart](ch-08-17-ospf-graceful-restart.md) and the
  [OSPFv3 sibling](ch-15-12-ospfv3-graceful-restart.md).
- **Adaptive SPF throttle** (`spf-interval`) — the IOS-XR-style
  exponential backoff (`initial` / `secondary` / `maximum` wait,
  FRR's `timers throttle spf`), per-area and shared with IS-IS,
  for both OSPFv2 and OSPFv3. Replaces the old fixed 1-second
  coalescing timer. See [Timer Configuration](ch-08-08-ospf-timers.md).
- **Send-side MinLSInterval** (`min-ls-interval`, RFC 2328 §12.4 /
  FRR `timers throttle lsa all`) — self-LSA re-origination is now
  rate-limited (Router-LSA and Network-LSA coalesce a burst of
  topology changes into one update), configurable for both OSPFv2 and
  OSPFv3. See [Timer Configuration](ch-08-08-ospf-timers.md).
- **Configurable MinLSArrival** (`min-ls-arrival`, RFC 2328 §13 /
  FRR `timers lsa min-arrival`) — the receive-side per-LSA rate limit
  was already enforced but fixed at 1 s; it is now tunable for both
  OSPFv2 and OSPFv3. See [Timer Configuration](ch-08-08-ospf-timers.md).
- **Virtual links** (RFC 2328 §15, `area <transit> virtual-link
  <router-id>`) — a synthetic backbone interface derived from the
  transit area's SPF, unicast OSPF over the transit area, the
  VirtualLink Router-LSA entry and transit-area V-bit; multi-hop
  transit via the full-path SPF backlink walk, and per-virtual-link
  authentication (simple / MD5 / key-chain). OSPFv2 only (`ospf6d`
  has no virtual links either). See
  [Multi-Area Routing and the ABR](ch-08-14-ospf-multi-area-abr.md#virtual-links).
