# Inter-AS MPLS/VPN Option B over SR-MPLS (RFC 4364 §10b)

## Overview

As a service provider running L3VPN across two autonomous systems
I want Inter-AS Option B: the ASBRs exchange VPNv4 routes directly over
a single-hop MP-eBGP session and re-advertise them with next-hop-self,
allocating a fresh local label and a swap ILM for each, so the VPN
crosses the AS boundary as a label switch — the ASBRs hold every VPN
route but no VRF, and the inter-AS link carries labelled VPNv4 packets.

## Test Topology

```
            AS 65000                                AS 65001
   ce1 ── pe1 ──── p1 ──── asbr1 ════════ asbr2 ──── p2 ──── pe2 ── ce2
          lo        lo       lo  172.16.0.0/30 lo      lo      lo
       1.1.1.1   1.1.1.2  1.1.1.3  (global)   2.2.2.3 2.2.2.2 2.2.2.1
   └ vrf-cust ┘                                            └ vrf-cust ┘
    10.1.0.0/30                                            10.2.0.0/30
```

## Notes

- Intra-AS: IS-IS L2 + segment-routing mpls; VPNv4 iBGP PE↔ASBR over
  the SR-MPLS core (the PE loopback next-hop is resolved by the IGP —
  no BGP-LU).
- Inter-AS (asbr1↔asbr2, 172.16.0.0/30): a single-hop **MP-eBGP VPNv4**
  session over a link in the GLOBAL table (NOT the IGP). The ASBRs run
  NO VRF: a received VPNv4 route sits in the global v4vpn RIB and is
  re-advertised with next-hop-self, a freshly allocated local label and
  a swap ILM (our label → received label, toward the original next-hop).
- A CE→CE packet is VPN-labelled PE→ASBR over the SR core; the ASBR
  swaps the VPN label and forwards a single labelled packet across the
  inter-AS link; the far ASBR swaps again over its SR core to the egress
  PE, which pops and delivers plain IP to the CE.

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Build the Inter-AS Option B topology and bring up every session | |
| SR-MPLS transport LSPs are installed on the core P routers | |
| The ASBRs hold every VPN prefix in the global VPNv4 table (no VRF) | |
| Each PE imports the remote-AS customer prefix into its VRF | |
| End-to-end customer forwarding across the AS boundary (VPNv4 label swap) | |
| Teardown topology | |
