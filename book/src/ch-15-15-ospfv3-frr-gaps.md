# Gaps Relative to FRR ospf6d

OSPFv3 features not yet implemented in zebra-rs:

- Discard (Null0) routes for active area ranges — the aggregation
  and suppression themselves are implemented.
- Redistribution `route-map` filtering (the zebra-rs sources are
  connected, static, kernel, IS-IS, and BGP, matching v2).
- Non-zero forwarding-address resolution on received externals.
- NBMA and point-to-multipoint network types.
- Configurable SPF throttling (SPF is coalesced behind a fixed
  1-second timer, as in v2).
- Configurable Instance ID (always 0 — one instance per link).

The balance runs the other way for Segment Routing: zebra-rs
OSPFv3 implements SR-MPLS (RFC 8666), SRv6 (RFC 9513), TI-LFA
fast-reroute, and Flexible Algorithm (RFC 9350), none of which
exist in `ospf6d`.
