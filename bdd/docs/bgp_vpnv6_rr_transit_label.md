# A VPNv6 next-hop-self transit advertises its own label and programs a swap ILM

## Overview

The VPNv6 twin of `bgp_vpnv4_rr_transit_label`. A route reflector that
only relays VPNv6 between iBGP clients passes every route through with
the originating PE's next-hop and VPN label unchanged and programs no
MPLS ILM. A router that rewrites the next-hop to itself — an Inter-AS
Option B transit ASBR, modelled here by turning `afi-safi vpnv6
next-hop-self` on at the reflector — must advertise a label of ITS OWN
and hold a swap ILM behind it, for the routes it already holds the
moment the knob is turned on, and must drop both again when it is
turned off. Review finding #8: VPNv6 had none of this — the received
label went on the wire behind the transit's own next-hop, so the peer
pushed a label the transit held no ILM for.

## Test Topology

```
  ┌───────────────────────────────────────────────┐
  │                      br0                      │
  └───────┬───────────────┬───────────────┬───────┘
          │               │               │
     ┌────┴────┐     ┌────┴────┐     ┌────┴────┐
     │   rr    │     │   pe1   │     │   pe2   │
     │ AS64512 │     │ AS64512 │     │ AS64512 │
     │ (RR,    │     │vrf-cust │     │vrf-cust │
     │ no VRF) │     │db8:1::/64│    │db8:2::/64│
     │ .1 / ::1│     │ .2 / ::2│     │ .3 / ::3│
     └─────────┘     └─────────┘     └─────────┘
       192.168.0.0/24 (sessions) + 2001:db8::/64 (VPNv6 next-hops)
```

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Setup topology and establish the VPNv6 sessions | |
| The reflector relays the VPNv6 routes and programs no MPLS label | |
| next-hop-self turns the reflector into a VPNv6 transit and labels the routes it already holds | |
| Removing next-hop-self releases the transit labels again | |
| Teardown topology | |
