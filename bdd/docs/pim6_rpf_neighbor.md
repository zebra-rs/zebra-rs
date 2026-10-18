# A PIMv6 Join names the upstream router by its Hello source

## Overview

r2 reaches the source through r1's global address, a static route's
nexthop. RFC 7761 sends the Join to RPF'(S,G) = NBR(RPF interface,
nexthop): the primary address, the Hello source, of the neighbor that
owns the nexthop, which for PIMv6 is its link-local. r2 used to name
the global in the Join's Upstream Neighbor field and in `show pim
ipv6 upstream`. r1, a zebra-rs, accepts any of its addresses, but FRR
takes a Join naming anything but its primary as one addressed to
another router, and never joins the tree.

r1's link-local is fixed so that the address can be matched.

## Test Topology

```
    r1 eth1 ------------------ eth2 r2 eth5 ------------ eth6 h2 (receiver)
       fe80::13:1                  2001:db8:15::1
       2001:db8:13::1/64           2001:db8:13::2/64
    r1 eth3 (dummy, 2001:db8:14::1/64, the source's subnet)
```

## Test Scenarios

| Scenario | Result |
|----------|--------|
| r2 joins the (S,G) tree through r1 | |
| The Join names r1's link-local | |
| show pim ipv6 upstream names r1's link-local | |
| Teardown topology | |
