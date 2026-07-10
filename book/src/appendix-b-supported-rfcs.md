# Appendix B: Supported RFCs and Internet-Drafts

This appendix lists the IETF standards that zebra-rs implements, grouped by
protocol area. Each entry names the document and gives a one-line summary of
what it specifies and how zebra-rs uses it. Foundational specifications that
several areas build on (Segment Routing architecture, TI-LFA, IGP Flexible
Algorithm, GTSM) are repeated in each relevant table so that every table reads
as a self-contained inventory.

Documents marked as an *Internet-Draft* were work-in-progress at the time of
implementation; the corresponding features track the referenced draft revision.

## BGP

| RFC / Internet-Draft | Description |
| --- | --- |
| RFC 4271 | A Border Gateway Protocol 4 (BGP-4) — the base path-vector protocol, FSM, and UPDATE processing. |
| RFC 4760 | Multiprotocol Extensions for BGP-4 (MP-BGP) — the MP_REACH / MP_UNREACH carriers for every AFI/SAFI. |
| RFC 2545 | Use of BGP-4 Multiprotocol Extensions for IPv6 inter-domain routing. |
| RFC 6793 | BGP support for four-octet (32-bit) Autonomous System numbers. |
| RFC 5492 | Capabilities Advertisement with BGP-4 — OPEN-message capability negotiation. |
| RFC 2918 | Route Refresh Capability for BGP-4. |
| RFC 7313 | Enhanced Route Refresh (Begin/End-of-RIB markers for graceful soft-reconfiguration). |
| RFC 7911 | Advertisement of Multiple Paths in BGP (Add-Path). |
| RFC 8654 | Extended Message support for BGP (messages larger than 4096 octets). |
| RFC 4724 | Graceful Restart Mechanism for BGP (End-of-RIB signalling). |
| RFC 9494 | Long-Lived Graceful Restart for BGP (LLGR_STALE / NO_LLGR communities). |
| RFC 1997 | BGP Communities Attribute — including enforced NO_EXPORT and NO_ADVERTISE semantics. |
| RFC 8092 | BGP Large Communities Attribute. |
| RFC 4360 | BGP Extended Communities Attribute. |
| RFC 9012 | Tunnel Encapsulation Attribute, including the Color extended community. |
| RFC 7311 | The Accumulated IGP Metric Attribute for BGP (AIGP). |
| RFC 7606 | Revised Error Handling for BGP UPDATE messages (treat-as-withdraw / attribute discard). |
| RFC 4456 | BGP Route Reflection — an alternative to full IBGP mesh. |
| RFC 7947 | Internet Exchange BGP Route Server behaviour. |
| RFC 2385 | Protection of BGP Sessions via the TCP MD5 Signature Option. |
| RFC 5925 | The TCP Authentication Option (TCP-AO). |
| RFC 5926 | Cryptographic Algorithms for the TCP Authentication Option. |
| RFC 5082 | The Generalized TTL Security Mechanism (GTSM) — eBGP multihop / ttl-security. |
| RFC 7705 | Autonomous System Migration mechanisms and their effect on AS_PATH (local-as). |
| RFC 6996 | Autonomous System (AS) Reservation for Private Use (remove-private-as range). |
| RFC 8950 | Advertising IPv4 NLRI with an IPv6 Next Hop (updates RFC 5549) — used for IPv6 unnumbered peering. |
| RFC 9830 | Advertising Segment Routing Policies in BGP (SR Policy, SAFI 73). |
| draft-ietf-bess-mup-safi | BGP Mobile User Plane (MUP) SAFI 85 — Type-1 Session Transformed and Type-2 Direct Segment routes. |

## OSPFv2

| RFC / Internet-Draft | Description |
| --- | --- |
| RFC 2328 | OSPF Version 2 — the base link-state IGP for IPv4. |
| RFC 5250 | The OSPF Opaque LSA Option — the carrier for TE and Segment Routing extensions. |
| RFC 3101 | The OSPF Not-So-Stubby Area (NSSA) Option. |
| RFC 3623 | Graceful OSPF Restart (restart signalling and helper mode). |
| RFC 5709 | OSPFv2 HMAC-SHA Cryptographic Authentication. |
| RFC 7474 | Security Extension for OSPFv2 when Using Manual Key Management (key rollover). |
| RFC 6987 | OSPF Stub Router Advertisement (max-metric on startup / administratively). |
| RFC 7770 | Extensions to OSPF for Advertising Optional Router Capabilities (Router Information LSA). |
| RFC 7684 | OSPFv2 Prefix/Link Attribute Advertisement (Extended Prefix / Extended Link LSAs). |
| RFC 8665 | OSPF Extensions for Segment Routing (SR-MPLS). |
| RFC 7471 | OSPF Traffic Engineering Metric Extensions (unidirectional delay / loss). |
| RFC 9492 | OSPF Application-Specific Link Attributes (ASLA). |
| RFC 9350 | IGP Flexible Algorithm (Flex-Algo) constraint-based SPF. |
| RFC 9855 | Topology-Independent Loop-Free Alternate (TI-LFA) fast reroute using Segment Routing. |

## OSPFv3

| RFC / Internet-Draft | Description |
| --- | --- |
| RFC 5340 | OSPF for IPv6 (OSPFv3) — the base link-state IGP for IPv6, including instance-id support. |
| RFC 5187 | OSPFv3 Graceful Restart. |
| RFC 7166 | Supporting Authentication Trailer for OSPFv3. |
| RFC 8362 | OSPFv3 Link State Advertisement (LSA) Extensibility (the E-… extended LSA family). |
| RFC 8666 | OSPFv3 Extensions for Segment Routing (SR-MPLS). |
| RFC 9513 | OSPFv3 Extensions for SRv6. |
| RFC 3101 | The OSPF Not-So-Stubby Area (NSSA) Option. |
| RFC 6987 | OSPF Stub Router Advertisement (max-metric). |
| RFC 9350 | IGP Flexible Algorithm (Flex-Algo) constraint-based SPF. |
| RFC 9855 | Topology-Independent Loop-Free Alternate (TI-LFA) fast reroute using Segment Routing. |

## IS-IS

| RFC / Internet-Draft | Description |
| --- | --- |
| ISO/IEC 10589 | Intermediate System to Intermediate System (IS-IS) — the base link-state routing standard. |
| RFC 1195 | Use of OSI IS-IS for Routing in TCP/IP and Dual Environments (IPv4 reachability). |
| RFC 5308 | Routing IPv6 with IS-IS. |
| RFC 5120 | Multi-Topology (MT) Routing in IS-IS. |
| RFC 5301 | Dynamic Hostname Exchange Mechanism for IS-IS. |
| RFC 5303 | Three-Way Handshake for IS-IS Point-to-Point Adjacencies. |
| RFC 5304 | IS-IS Cryptographic Authentication (MD5). |
| RFC 5310 | IS-IS Generic Cryptographic Authentication (HMAC-SHA family). |
| RFC 5305 | IS-IS Extensions for Traffic Engineering (extended reachability TLVs). |
| RFC 5306 | Restart Signaling for IS-IS (graceful restart). |
| RFC 5307 | IS-IS Extensions in Support of GMPLS — Shared Risk Link Group (SRLG) advertisement. |
| RFC 5311 | Simplified Extension of the LSP Space for IS-IS (LSP fragmentation). |
| RFC 6119 | IPv6 Traffic Engineering in IS-IS (IPv6 SRLG and TE). |
| RFC 6232 | Purge Originator Identification TLV for IS-IS. |
| RFC 7794 | IS-IS Prefix Attributes for Extended IPv4 and IPv6 Reachability. |
| RFC 8570 | IS-IS Traffic Engineering Attributes (unidirectional delay / loss extended metrics). |
| RFC 8667 | IS-IS Extensions for Segment Routing (SR-MPLS). |
| RFC 9479 | IS-IS Application-Specific Link Attributes (ASLA). |
| RFC 9352 | IS-IS Extensions to Support Segment Routing over the IPv6 Data Plane (SRv6). |
| RFC 9350 | IGP Flexible Algorithm (Flex-Algo) constraint-based SPF. |
| RFC 9855 | Topology-Independent Loop-Free Alternate (TI-LFA) fast reroute using Segment Routing. |

## BFD

| RFC / Internet-Draft | Description |
| --- | --- |
| RFC 5880 | Bidirectional Forwarding Detection (BFD) — the base protocol and Echo function. |
| RFC 5881 | BFD for IPv4 and IPv6 (single-hop). |
| RFC 5882 | Generic Application of BFD — client integration for BGP, OSPF and IS-IS. |
| RFC 5883 | BFD for Multihop Paths. |
| RFC 5082 | The Generalized TTL Security Mechanism (GTSM) — TTL=255 check on single-hop sessions. |

## SRv6

| RFC / Internet-Draft | Description |
| --- | --- |
| RFC 8402 | Segment Routing Architecture. |
| RFC 8754 | IPv6 Segment Routing Header (SRH) and Reduced SRH. |
| RFC 8986 | SRv6 Network Programming — End, End.X and End.DT4/DT6/DT46 endpoint behaviors. |
| RFC 9800 | Compressed SRv6 Segment List Encoding (NEXT-C-SID / micro-SID). |
| RFC 9513 | OSPFv3 Extensions for SRv6 (IGP advertisement of locators and End SIDs). |
| RFC 9352 | IS-IS Extensions to Support SRv6 (IGP advertisement of locators and End SIDs). |
| RFC 9252 | BGP Overlay Services based on SRv6 (L3VPN / EVPN service SIDs). |
| draft-ietf-rtgwg-srv6-egress-protection | SRv6 egress-node protection with a mirror SID. |

## SR-MPLS

| RFC / Internet-Draft | Description |
| --- | --- |
| RFC 8402 | Segment Routing Architecture. |
| RFC 8660 | Segment Routing with the MPLS Data Plane. |
| RFC 3032 | MPLS Label Stack Encoding (the SR-MPLS forwarding label stack). |
| RFC 8665 | OSPF Extensions for Segment Routing (SR-MPLS). |
| RFC 8666 | OSPFv3 Extensions for Segment Routing (SR-MPLS). |
| RFC 8667 | IS-IS Extensions for Segment Routing (SR-MPLS). |
| RFC 8669 | BGP Prefix Segment Identifiers (BGP Prefix-SID attribute). |
| RFC 8679 | MPLS Egress Protection Framework (mirror SID egress protection). |
| RFC 9256 | Segment Routing Policy Architecture (candidate-path model). |

## L3VPN

| RFC / Internet-Draft | Description |
| --- | --- |
| RFC 4364 | BGP/MPLS IP Virtual Private Networks (VPNv4), including Inter-AS Options A/B/C/AB. |
| RFC 4659 | BGP-MPLS IP VPN Extension for IPv6 VPN (VPNv6). |
| RFC 4798 | Connecting IPv6 Islands over IPv4 MPLS using IPv6 Provider Edge Routers (6PE). |
| RFC 8277 | Using BGP to Bind MPLS Labels to Address Prefixes (labeled unicast, SAFI 4; obsoletes RFC 3107). |
| RFC 4684 | Constrained Route Distribution for BGP/MPLS IP VPNs — Route Target Constraint (RTC). |
| RFC 9252 | BGP Overlay Services based on SRv6 — L3VPN over an SRv6 underlay (per-VRF End.DT46). |
| RFC 8950 | Advertising IPv4 NLRI with an IPv6 Next Hop (VPN v4-over-v6 next hops). |

## EVPN

| RFC / Internet-Draft | Description |
| --- | --- |
| RFC 7432 | BGP MPLS-Based Ethernet VPN (EVPN) — the base control plane. |
| RFC 8365 | A Network Virtualization Overlay Solution Using EVPN (EVPN over VXLAN). |
| RFC 9136 | IP Prefix Advertisement in EVPN (Type-5 routes). |
| RFC 8584 | Framework for EVPN Designated Forwarder (DF) Election Extensibility. |
| RFC 8214 | Virtual Private Wire Service (VPWS) Support in EVPN (E-Line services). |
| RFC 9251 | IGMP and MLD Proxy for EVPN (selective multicast). |
| RFC 9574 | Optimized Ingress Replication Solution for EVPN. |
| RFC 9572 | Multicast and Ethernet VPN with Segmentation — BUM tunnel segmentation (route types 9/10/11). |
| RFC 9524 | Segment Routing point-to-multipoint (P2MP) replication trees for BUM delivery. |
| draft-ietf-bess-mvpn-evpn-sr-p2mp | MVPN/EVPN steering over SR point-to-multipoint (P2MP) replication segments. |
