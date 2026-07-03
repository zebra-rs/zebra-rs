# Gaps Relative to FRR ospf6d

OSPFv3 features not yet implemented in zebra-rs:

- **ABR Inter-Area-Prefix (0x2003) / Inter-Area-Router (0x2004)
  origination** — the most significant gap: multi-area topologies
  form and run per-area SPF, but a zebra-rs v3 ABR does not
  generate inter-area routes. See
  [Multi-Area Topologies and the ABR](ch-15-04-ospfv3-multi-area-abr.md).
- Area ranges (`area <id> range` prefix aggregation).
- Instance-level redistribution of sources other than `bgp`
  (`connected`, `static`, kernel routes); per-NSSA-area `connected`
  is the only other source today.
- Graceful-restart configuration and restarter mode — v3 is
  helper-only with fixed defaults (v2 has both roles; `ospf6d` has
  helper configuration and restarting support).
- A native `router ospfv3` authentication config path — the
  RFC 7166 Authentication Trailer is implemented, but its keys are
  configured through the shared v2 interface tree (`ospf6d` has
  `ipv6 ospf6 authentication` per interface).
- Passive interfaces.
- Instance-level `default-information originate` (the NSSA-scoped
  default via `nssa-default-originate` is implemented).
- Inter-area ASBR resolution (Inter-Area-Router-LSA fallback) and
  non-zero forwarding-address resolution on received externals.
- NBMA and point-to-multipoint network types.
- Configurable SPF throttling (SPF is coalesced behind a fixed
  1-second timer, as in v2).
- Configurable Instance ID (always 0 — one instance per link).

The balance runs the other way for Segment Routing: zebra-rs
OSPFv3 implements SR-MPLS (RFC 8666), SRv6 (RFC 9513), TI-LFA
fast-reroute, and Flexible Algorithm (RFC 9350), none of which
exist in `ospf6d`.
