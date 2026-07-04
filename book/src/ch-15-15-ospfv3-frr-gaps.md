# Gaps Relative to FRR ospf6d

OSPFv3 features not yet implemented in zebra-rs:

- NBMA and point-to-multipoint network types.

Forwarding-address origination (NSSA Type-7, F-flag) and resolution
on received externals are implemented for OSPFv3 identically to v2
— see [the v2 gaps page](ch-08-12-ospf-frr-gaps.md).

The per-interface Instance ID (RFC 5340 §A.3.1) is configurable —
`instance-id` on the interface entry, enforced on receive — see
[Per-Interface Settings](ch-15-06-ospfv3-per-interface.md).

Stub-router advertisement (`max-metric router-lsa`, `ospf6d`'s
`stub-router`) is implemented via the RFC 5340 R/V6 option bits,
including receive-side transit exclusion — see
[Timer Configuration](ch-08-08-ospf-timers.md#stub-router-max-metric-router-lsa).

Redistribution `route-map` filtering is implemented for OSPFv3
identically to v2 (policy lists shared with BGP, live
re-application) — see
[Route Redistribution](ch-08-15-ospf-redistribution.md#route-map-filtering).
The `redistribute table` source is OSPFv2-only in zebra-rs, but
that is parity, not a gap: `ospf6d` has no table source either.

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
