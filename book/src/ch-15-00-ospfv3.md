# OSPFv3 — OSPF for IPv6

OSPFv3 (RFC 5340) carries the OSPF link-state model to IPv6. It
keeps the protocol machinery of OSPFv2 — areas, the Hello / DBD /
LS-Request / LS-Update / LS-Ack exchanges, the IFSM and NFSM state
machines, flooding with retransmission, SPF — but restructures what
the LSAs carry:

- **Per-link, not per-subnet.** Packets are exchanged over IPv6
  link-local addresses (`fe80::…`); a neighbor is identified by its
  Router ID, not by an interface address. The Router ID itself
  remains a 32-bit value written as an IPv4-style dotted quad.
- **Topology and addressing are decoupled.** Router-LSAs and
  Network-LSAs describe pure topology; the IPv6 prefixes live in
  separate Intra-Area-Prefix-LSAs, and each link's link-local
  address and prefixes ride a link-scoped Link-LSA. Renumbering
  therefore doesn't churn the SPF topology.
- **No per-packet authentication field.** RFC 5340 delegated
  security to IPsec; zebra-rs implements the modern RFC 7166
  Authentication Trailer instead.
- **Extended LSAs** (RFC 8362, the `E-…` LSA family) carry the
  Segment Routing extensions: SR-MPLS (RFC 8666) and SRv6
  (RFC 9513).

zebra-rs shares one generic OSPF core between v2 and v3, so the
configuration shape mirrors [the OSPFv2 chapter](ch-08-00-ospf.md)
— a v3 config differs from v2 only in the top-level keyword
(`router ospfv3`). The implementation is validated against FRR's
`ospf6d` and by the BDD suite (adjacency, NSSA, SRv6, TI-LFA,
router-id change, BFD topologies).

This chapter documents the OSPFv3 configuration surface. Where
behavior is identical to OSPFv2 the pages summarize and link to the
v2 chapter; v3-specific behavior — link-local transport, the LSA
model, SRv6, and the current v2/v3 feature asymmetries — is covered
in full.
