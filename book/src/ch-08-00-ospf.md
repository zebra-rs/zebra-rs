# OSPFv2 — Open Shortest Path First

OSPFv2 (RFC 2328) is a link-state interior gateway protocol for IPv4.
Routers flood Link State Advertisements (LSAs) describing local
interface state, attached prefixes, and adjacencies; every router
independently runs Dijkstra over the resulting database to compute
shortest paths.

zebra-rs implements OSPFv2 with the standard area model (a backbone
area `0.0.0.0` and arbitrarily many non-backbone areas joined to it),
Hello / Database-Description / LSA-Update / LSA-Request /
LSA-Acknowledgement processing, the canonical IFSM and NFSM state
machines, Fletcher (RFC 905 §A.4.1) LSA checksums, retransmission
with per-neighbor `ls_rxmt` tracking, delayed LSAck aggregation,
opaque-LSA (RFC 5250) processing for Segment Routing extensions,
and SPF with route installation into the system RIB. Interop has
been validated against FRR's `ospfd`.

This section documents the configuration surface. See `router ospf`
under `/router/ospf` in the YANG schema for the full configuration
tree.
