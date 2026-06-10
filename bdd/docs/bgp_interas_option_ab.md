# Inter-AS MPLS/VPN Option AB over SR-MPLS (RFC 4364 hybrid)

## Overview

As a service provider running L3VPN across two autonomous systems
I want Inter-AS Option AB: the ASBRs keep a per-VPN VRF and forward
through it (the VPN label terminates at the ASBR → VRF lookup →
re-impose, like Option A), but exchange every VPN over a single MP-eBGP
VPNv4 session on one labelled link (like Option B). Each ASBR's
`inter-as-hybrid` VRF re-exports the VPNv4 routes it imports, relaying
the remote AS's prefixes to its own PEs.

## Test Topology

```
            AS 65000                                AS 65001
   ce1 ── pe1 ──── p1 ──── asbr1 ════════ asbr2 ──── p2 ──── pe2 ── ce2
          lo        lo       lo  172.16.0.0/30 lo      lo      lo
       1.1.1.1   1.1.1.2  1.1.1.3  (global)   2.2.2.3 2.2.2.2 2.2.2.1
   └ vrf-cust ┘        └ vrf-cust ┘        └ vrf-cust ┘    └ vrf-cust ┘
    10.1.0.0/30        (transit, no CE)   (transit, no CE)  10.2.0.0/30
```

## Notes

- Intra-AS: IS-IS L2 + segment-routing mpls; VPNv4 iBGP PE↔ASBR over
  the SR-MPLS core.
- Inter-AS (asbr1↔asbr2, 172.16.0.0/30): a single-hop **MP-eBGP VPNv4**
  session over a link in the GLOBAL table. Each ASBR holds vrf-cust (no
  interface, no CE) with `inter-as-hybrid`, so it imports the VPNv4 it
  receives into the VRF (for per-VRF forwarding) AND re-exports it onward.
- A CE→CE packet is VPN-labelled PE→ASBR over the SR core; at each ASBR
  the label terminates (DecapVrf → VRF lookup) and a new label is
  imposed — toward the peer ASBR (single label on the inter-AS link) or
  toward the egress PE over its SR core.

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Build the Inter-AS Option AB topology and bring up every session | |
| SR-MPLS transport LSPs are installed on the core P routers | |
| Each ASBR holds every VPN prefix in its per-VPN VRF (the "A" half) | |
| Each PE imports the remote-AS customer prefix into its VRF | |
| End-to-end customer forwarding across the AS boundary (per-VRF label swap) | |
| Teardown topology | |
