# Gaps Relative to FRR ospf6d

OSPFv3 features not yet implemented in zebra-rs:

- Redistribution `route-map` filtering (the zebra-rs sources are
  connected, static, kernel, IS-IS, and BGP, matching v2).
- Non-zero forwarding-address resolution on received externals.
- NBMA and point-to-multipoint network types.
- Configurable Instance ID (always 0 — one instance per link).

The adaptive SPF throttle (`spf-interval`) and the send-side
MinLSInterval (`min-ls-interval`) are both configurable for OSPFv3,
identical to v2 — see
[Timer Configuration](ch-08-08-ospf-timers.md). MinLSInterval on v3
actually goes beyond `ospf6d`, which has no `timers throttle lsa`
command at all (only the receive-side `timers lsa min-arrival`).

The balance runs the other way for Segment Routing: zebra-rs
OSPFv3 implements SR-MPLS (RFC 8666), SRv6 (RFC 9513), TI-LFA
fast-reroute, and Flexible Algorithm (RFC 9350), none of which
exist in `ospf6d`.
