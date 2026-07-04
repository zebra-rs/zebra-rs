# Gaps Relative to FRR ospf6d

OSPFv3 features not yet implemented in zebra-rs:

- Non-zero forwarding-address resolution on received externals.
- NBMA and point-to-multipoint network types.
- Configurable Instance ID (always 0 — one instance per link).

Redistribution `route-map` filtering is implemented for OSPFv3
identically to v2 (policy lists shared with BGP, live
re-application) — see
[Route Redistribution](ch-08-15-ospf-redistribution.md#route-map-filtering).

The adaptive SPF throttle (`spf-interval`), the send-side
MinLSInterval (`min-ls-interval`), and the receive-side MinLSArrival
(`min-ls-arrival`) are all configurable for OSPFv3, identical to v2 —
see [Timer Configuration](ch-08-08-ospf-timers.md). MinLSInterval on
v3 actually goes beyond `ospf6d`, which has no `timers throttle lsa`
command at all (only the receive-side `timers lsa min-arrival`, which
zebra-rs also exposes).

The balance runs the other way for Segment Routing: zebra-rs
OSPFv3 implements SR-MPLS (RFC 8666), SRv6 (RFC 9513), TI-LFA
fast-reroute, and Flexible Algorithm (RFC 9350), none of which
exist in `ospf6d`.
