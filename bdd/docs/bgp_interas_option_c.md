# Inter-AS MPLS/VPN Option C over SR-MPLS (RFC 4364 §10c)

## Overview

As a service provider running L3VPN across two autonomous systems
I want Inter-AS Option C: the ASBRs exchange only labeled IPv4 (BGP-LU)
for the PE loopbacks and hold no VPN state, while the PEs run a direct
multihop MP-eBGP VPNv4 session whose next-hop (the remote PE loopback)
is resolved across the AS boundary through the BGP-LU LSP, with SR-MPLS
providing the intra-AS transport.
This mirrors Cisco's "Configuration and Verification of L3 MPLS VPN
Inter-AS Option C" (doc 200523), streamlined to one PE + one P + one
ASBR per AS and a direct PE↔PE VPNv4 session (no route reflector — the
originating PE's next-hop-self is already the correct egress, so no
next-hop-unchanged is needed; the ASBR→PE iBGP-LU leg uses next-hop-self
instead).

## Test Topology

```
            AS 65000                              AS 65001
   ce1 --- pe1 --- p1 --- asbr1 ===== asbr2 --- p2 --- pe2 --- ce2
  10.1.0.2 lo       lo     lo   172.16  lo       lo     lo   10.2.0.2
        1.1.1.1 1.1.1.2 1.1.1.3 .0.0/30 2.2.2.3 2.2.2.2 2.2.2.1
        (sid 1) (sid 2) (sid 3)         (sid 6) (sid 5) (sid 4)
   \__vrf-cust_/                                       \_vrf-cust__/
     10.1.0.0/30                                         10.2.0.0/30
```

## Notes

- Intra-AS: IS-IS L2 + segment-routing mpls; loopback Prefix-SIDs give
  the transport LSP (SRGB base 16000 → labels 16001..16006). P routers
  perform the real SR transit swap / PHP.
- Inter-AS (asbr1↔asbr2, 172.16.0.0/30): eBGP labeled-unicast only —
  PE loopback /32s exchanged with labels, no IGP, no VPN state.
- ASBR↔PE (intra-AS): iBGP labeled-unicast with next-hop-self, so the
  PE resolves the ASBR (via IS-IS) and pushes the ASBR's swap label.
- PE↔PE: multihop eBGP VPNv4 between loopbacks. The session itself
  rides the BGP-LU LSP, so "Established" already proves end-to-end
  labeled forwarding works before any data packet is sent.
- The CE↔CE ping exercises the full label stack: SR transport (outer)
  + BGP-LU (AS crossing) + VPN (innermost).

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Build the Inter-AS Option C topology and bring up every session | |
| SR-MPLS transport LSPs are installed on the core P routers | |
| ASBRs exchange PE loopbacks via BGP labeled-unicast, holding no VPN state | |
| Each PE learns the remote PE loopback through the BGP-LU chain | |
| VPNv4 customer routes are exchanged directly between the PEs | |
| End-to-end customer forwarding across the AS boundary (SR + BGP-LU + VPN) | |
| Teardown topology | |
