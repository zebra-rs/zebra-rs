# ORIGINATOR_ID and CLUSTER_LIST received from an eBGP peer are discarded (IPv6)

## Overview

As a network operator
I want ORIGINATOR_ID and CLUSTER_LIST arriving over an eBGP session to
be discarded on ingest (RFC 7606 §7.9 / §7.10, "attribute discard")
So that another AS's route-reflection state can neither make my routers
drop its routes as reflection loops nor be relayed into my AS.

Both attributes describe reflection inside the AS that set them. Kept
from an eBGP peer, they are checked against the local router-id — a
neighbor AS whose reflector happens to share it (private router-ids
collide easily) gets its routes dropped at the border — and they ride
along when the border router hands the route to its iBGP peers, where
a match on any of their router-ids drops the route there. Every real
router strips both on eBGP egress, so only a scripted speaker can put
the DUT's ingress on the spot. A malformed instance from an external
neighbor is discarded too: it must cost neither the route nor the
session.

## Test Topology

```
  ┌─────────────────────────────────────────────────────────┐
  │                          br0                            │
  └───────┬────────────────────┬────────────────────┬───────┘
     ┌────┴────┐          ┌────┴────┐          ┌────┴────┐
     │   h1    │          │   z1    │          │   z2    │
     │ scripted│          │  (DUT)  │          │ zebra-rs│
     │  eBGP   │─eBGP────▶│ AS65050 │────iBGP─▶│ AS65050 │
     │ AS65051 │          │192.168. │          │192.168. │
     │ .45.2/24│          │ 45.1/24 │          │ 45.3/24 │
     └─────────┘          └─────────┘          └─────────┘
```

## Notes

h1 runs tests/scripts/bgp_attr_inject_send.py. At session-up it
announces, with next-hop 2001:db8:45::2 and AS_PATH 65051 in
MP_REACH_NLRI:
- 2001:db8:c0::/64: no reflection attributes (the control);
- 2001:db8:c1::/64: ORIGINATOR_ID 192.168.45.1 (z1's router-id);
- 2001:db8:c2::/64: CLUSTER_LIST 192.0.2.99 192.168.45.1 (names z1);
- 2001:db8:c3::/64: ORIGINATOR_ID 192.168.45.3 (z2's router-id);
- 2001:db8:c4::/64: CLUSTER_LIST 192.0.2.99 192.168.45.3 (names z2).
On the trigger file /tmp/bgp_ebgp_rr_attr_discard_v6.go it announces
2001:db8:c5::/64 with a 3-octet ORIGINATOR_ID and 2001:db8:c6::/64 with a
5-octet CLUSTER_LIST.

## Config Files

- z1.yaml: DUT — eBGP to h1 (passive), iBGP to z2; not a reflector;
  sessions over IPv4 carrying IPv6 unicast.
- z2.yaml: iBGP peer of z1.

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Setup topology and establish sessions | |
| The control prefix reaches z1 and z2 | |
| Reflection attributes naming the DUT itself do not cost the route at the border | |
| Reflection attributes from the eBGP peer are not relayed into the AS | |
| A malformed ORIGINATOR_ID or CLUSTER_LIST from the eBGP peer costs neither route nor session | |
| Teardown topology | |
