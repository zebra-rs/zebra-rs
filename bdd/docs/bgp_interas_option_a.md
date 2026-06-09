# Inter-AS MPLS/VPN Option A over SR-MPLS (RFC 4364 §10a)

## Overview

As a service provider running L3VPN across two autonomous systems
I want Inter-AS Option A: the ASBRs are back-to-back PEs joined by a
per-VPN VRF interface, over which they run a PE-CE eBGP session inside
the VRF. The VPN label terminates at each ASBR — the inter-AS link
carries plain IP inside the VRF — and each AS runs an ordinary intra-AS
L3VPN (PE↔ASBR VPNv4 over an SR-MPLS core).

## Test Topology

```
            AS 65000                              AS 65001
   ce1 ── pe1 ──── p1 ──── asbr1 ─── asbr2 ──── p2 ──── pe2 ── ce2
          lo        lo       lo  172.16  lo      lo      lo
       1.1.1.1   1.1.1.2  1.1.1.3 .0.0/30 2.2.2.3 2.2.2.2 2.2.2.1
   └ vrf-cust ┘          └ vrf ┘ (in VRF) └ vrf ┘       └ vrf-cust ┘
    10.1.0.0/30                                         10.2.0.0/30
```

## Notes

- Intra-AS: IS-IS L2 + segment-routing mpls; VPNv4 iBGP PE↔ASBR over
  the SR-MPLS core (the PE loopback next-hop is resolved by the IGP —
  no BGP-LU). ASBR1 and PE1 are both PEs of AS 65000; likewise AS 65001.
- Inter-AS (asbr1↔asbr2, 172.16.0.0/30): the link is in `vrf-cust` on
  both ASBRs (NOT in the IGP). They run a **PE-CE eBGP session inside
  vrf-cust**. Routes learned there are re-exported to VPNv4; imported
  VPNv4 routes are advertised over it. Plain IP on the wire.
- A CE→CE packet is VPN-labeled PE→ASBR, decapsulated to plain IP at
  the ASBR, forwarded over the inter-AS VRF link, then re-labeled
  ASBR→PE in the far AS.

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Build the Inter-AS Option A topology and bring up every session | |
| SR-MPLS transport LSPs are installed on the core P routers | |
| The customer prefixes cross the AS boundary via the per-VRF PE-CE eBGP | |
| Each PE imports the remote-AS customer prefix into its VRF | |
| End-to-end customer forwarding across the AS boundary (VPN + back-to-back VRF) | |
| Teardown topology | |
