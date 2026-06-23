# OSPF — Open Shortest Path First

OSPF is a link-state interior gateway protocol. Routers flood Link
State Advertisements (LSAs) describing local interface state, attached
prefixes, and adjacencies; every router independently runs Dijkstra
over the resulting database to compute shortest paths.

zebra-rs supports both versions of the protocol: **OSPFv2** (RFC 2328)
for IPv4 and **OSPFv3** (RFC 5340) for IPv6. Both implement the
standard area model (a backbone area `0.0.0.0` and arbitrarily many
non-backbone areas joined to it), Hello / Database-Description /
LSA-Update / LSA-Request / LSA-Acknowledgement processing, the
canonical IFSM and NFSM state machines, Fletcher (RFC 905 §A.4.1) LSA
checksums, retransmission with per-neighbor `ls_rxmt` tracking, delayed
LSAck aggregation, and SPF with route installation into the system RIB.
OSPFv2 additionally carries opaque LSAs (RFC 5250) for Segment Routing
extensions. Both versions have been validated against FRR's `ospfd`
and `ospf6d`.

This section documents the configuration surface. See `router ospf`
under `/router/ospf` in the YANG schema for the full configuration
tree.
