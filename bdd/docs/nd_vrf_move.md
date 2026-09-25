# Router Advertisements survive enslaving the interface into a VRF

## Overview

As an operator running IPv6 RA on an interface that later joins a VRF
I want `interface i1 vrf blue` to leave the interface advertising
so that moving a link into a VRF is a routing-table change and not a
silent loss of RA on that link.

ND is a single process-wide instance — unlike OSPF / IS-IS / BGP it is
not re-spawned per VRF — so it has to follow interfaces across VRF
boundaries itself. It used to subscribe to the RIB with the default
`vrf_id 0` binding, and `Rib::iter_link_subs` only delivers a link
event to subscribers whose `vrf_id` matches the link's VRF. RIB reports
a live cross-VRF move as `api_link_del_vrf(ifindex, old)` followed by
`api_link_add_vrf(link, new)`, so a vrf-0 subscriber saw only the
`LinkDel` half: `Nd::process_link_del` released the sender and the
matching `LinkAdd` — the one that would have re-applied the operator's
name-keyed RA config — was addressed to the VRF's subscribers instead
and never arrived. RA stopped for good, and `show ipv6 nd interface i1`
stopped reporting the interface at all.

This is the regression test for that: it fails on a vrf-0 subscription
and passes with `global_links`.

## Test Topology

```
        (i1)                                   (i1)
    ┌────┴────┐                            ┌────┴────┐
    │   z1    │────────── P2P ─────────────│   z2    │
    │ RA on   │       fe80:: <-> fe80::    │ RA on   │
    │ vrf blue│                            │ default │
    └─────────┘                            └─────────┘
```

## Notes

z2 exists only to hold the far end of the veth up (so i1 on z1 keeps
IFF_LOWER_UP and is not suspended by the link-state gate) and to send
RAs of its own so z1's receive counters move.

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Setup topology | |
| RA keeps running after the interface is enslaved into a VRF | |
| Teardown topology | |
